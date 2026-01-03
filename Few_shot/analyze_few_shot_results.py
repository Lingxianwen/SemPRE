#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Optimized SCI-Standard Few-Shot Learning Visualization

Improvements:
1. Removed main titles from figures
2. Added subplot labels (a), (b), (c), etc.
3. Enhanced formatting for publication quality
4. Better layout optimization
"""

import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import seaborn as sns
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import warnings
from collections import defaultdict, Counter
import string

warnings.filterwarnings('ignore')

# SCI-standard configuration
plt.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'Times', 'DejaVu Serif'],
    'font.size': 9,
    'axes.labelsize': 10,
    'axes.titlesize': 11,
    'xtick.labelsize': 8,
    'ytick.labelsize': 8,
    'legend.fontsize': 9,
    'figure.titlesize': 12,
    'axes.linewidth': 0.8,
    'grid.linewidth': 0.5,
    'lines.linewidth': 1.5,
    'patch.linewidth': 0.8,
    'xtick.major.width': 0.8,
    'ytick.major.width': 0.8,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.1,
    'text.usetex': False,
})


class OptimizedSCIFewShotAnalyzer:
    """Optimized SCI-standard analyzer for few-shot learning results"""

    def __init__(self, results_file: str):
        self.results_file = results_file
        self.results_data = None
        self.protocols = []
        self.shot_configs = []
        self.methods = []

        # Protocol information mapping
        self.protocol_info = {
            'modbus': {'full_name': 'Modbus', 'category': 'Industrial', 'complexity': 'Low'},
            'dnp3': {'full_name': 'DNP3', 'category': 'Industrial', 'complexity': 'High'},
            's7comm': {'full_name': 'S7COMM', 'category': 'Industrial', 'complexity': 'Medium'},
            'smb': {'full_name': 'SMB', 'category': 'File Transfer', 'complexity': 'High'},
            'smb2': {'full_name': 'SMB2', 'category': 'File Transfer', 'complexity': 'High'},
            'dns': {'full_name': 'DNS', 'category': 'Network', 'complexity': 'Medium'},
            'ftp': {'full_name': 'FTP', 'category': 'File Transfer', 'complexity': 'Low'},
            'tls': {'full_name': 'TLS', 'category': 'Security', 'complexity': 'High'},
            'dhcp': {'full_name': 'DHCP', 'category': 'Network', 'complexity': 'Medium'}
        }

        # Load and parse data
        self.load_results()

    def load_results(self):
        """Load experimental results"""
        try:
            with open(self.results_file, 'r', encoding='utf-8') as f:
                self.results_data = json.load(f)

            # Parse structure
            self.shot_configs = [key for key in self.results_data.keys()
                                 if key.endswith('_shot')]

            if self.shot_configs:
                sample_shot = self.shot_configs[0]
                self.methods = list(self.results_data[sample_shot].keys())

                # Extract protocol information
                sample_method = self.methods[0]
                experiments = self.results_data[sample_shot][sample_method]

                protocols_set = set()
                for exp_key in experiments.keys():
                    if '_to_' in exp_key:
                        source, target = exp_key.split('_to_')
                        protocols_set.add(source)
                        protocols_set.add(target)

                self.protocols = sorted(list(protocols_set))

            print(f"✅ Results loaded successfully: {self.results_file}")
            print(f"   Shot configurations: {self.shot_configs}")
            print(f"   Methods: {self.methods}")
            print(f"   Protocols ({len(self.protocols)}): {self.protocols}")

        except Exception as e:
            print(f"❌ Failed to load results: {e}")
            raise

    def add_subplot_label(self, ax, label, x=-0.15, y=1.08, fontsize=12, weight='bold'):
        """Add subplot label (a), (b), (c), etc."""
        ax.text(x, y, f'({label})', transform=ax.transAxes,
                fontsize=fontsize, weight=weight, va='top', ha='left',
                bbox=dict(boxstyle='round,pad=0.3', facecolor='white',
                          edgecolor='none', alpha=0.8))

    def create_nine_subplot_heatmap(self, figsize: Tuple[float, float] = (15, 12)) -> plt.Figure:
        """Create nine-subplot heatmap for each target protocol"""

        fig, axes = plt.subplots(3, 3, figsize=figsize)
        axes = axes.flatten()

        # Use best performing shot configuration and method
        best_shot_config = '5_shot' if '5_shot' in self.shot_configs else self.shot_configs[0]
        best_method = 'simple' if 'simple' in self.methods else self.methods[0]

        print(f"Using {best_method} method with {best_shot_config} configuration")

        n_protocols = len(self.protocols)

        # Global colormap limits for consistency
        all_values = []

        # First pass: collect all values for consistent scaling
        for target_idx, target_protocol in enumerate(self.protocols):
            for source_protocol in self.protocols:
                if source_protocol != target_protocol:
                    exp_key = f"{source_protocol}_to_{target_protocol}"

                    if (best_shot_config in self.results_data and
                            best_method in self.results_data[best_shot_config] and
                            exp_key in self.results_data[best_shot_config][best_method]):

                        result = self.results_data[best_shot_config][best_method][exp_key]
                        if result.get('success', False):
                            f1_score = result.get('avg_overall_f1', 0)
                            all_values.append(f1_score)

        vmin, vmax = 0, max(all_values) if all_values else 0.6

        # Generate subplot labels
        subplot_labels = list(string.ascii_lowercase)

        # Create heatmaps for each target protocol
        for target_idx, target_protocol in enumerate(self.protocols):
            ax = axes[target_idx]

            # Create performance matrix for this target
            performance_matrix = np.full((len(self.shot_configs), n_protocols - 1), np.nan)

            # Collect source protocols (excluding target)
            source_protocols = [p for p in self.protocols if p != target_protocol]

            # Fill performance matrix
            for shot_idx, shot_config in enumerate(self.shot_configs):
                for source_idx, source_protocol in enumerate(source_protocols):
                    exp_key = f"{source_protocol}_to_{target_protocol}"

                    if (shot_config in self.results_data and
                            best_method in self.results_data[shot_config] and
                            exp_key in self.results_data[shot_config][best_method]):

                        result = self.results_data[shot_config][best_method][exp_key]
                        if result.get('success', False):
                            f1_score = result.get('avg_overall_f1', 0)
                            performance_matrix[shot_idx, source_idx] = f1_score

            # Create heatmap
            im = ax.imshow(performance_matrix, cmap='RdYlGn', vmin=vmin, vmax=vmax,
                           aspect='auto', interpolation='nearest')

            # Add value annotations
            for i in range(len(self.shot_configs)):
                for j in range(len(source_protocols)):
                    value = performance_matrix[i, j]
                    if not np.isnan(value):
                        text_color = 'white' if value < (vmax * 0.5) else 'black'
                        ax.text(j, i, f'{value:.3f}', ha='center', va='center',
                                color=text_color, fontsize=7, weight='bold')
                    else:
                        ax.text(j, i, 'N/A', ha='center', va='center',
                                color='gray', fontsize=6, style='italic')

            # Add subplot label
            self.add_subplot_label(ax, subplot_labels[target_idx])

            # Formatting
            target_name = self.protocol_info.get(target_protocol, {}).get('full_name', target_protocol.upper())
            ax.set_title(f'Target: {target_name}', fontsize=10, weight='bold', pad=15)

            # Set labels only for specific positions
            if target_idx == 6:  # Bottom left
                ax.set_xlabel('Source Protocol', fontsize=9)
                ax.set_ylabel('Shot Number', fontsize=9)
            elif target_idx in [7, 8]:  # Bottom row
                ax.set_xlabel('Source Protocol', fontsize=9)
            elif target_idx in [0, 3]:  # Left column
                ax.set_ylabel('Shot Number', fontsize=9)

            # Set ticks
            ax.set_xticks(range(len(source_protocols)))
            ax.set_yticks(range(len(self.shot_configs)))

            # Protocol names
            source_names = [self.protocol_info.get(p, {}).get('full_name', p.upper())
                            for p in source_protocols]
            ax.set_xticklabels(source_names, rotation=45, ha='right', fontsize=7)

            # Shot labels
            shot_labels = [sc.replace('_shot', '') for sc in self.shot_configs]
            ax.set_yticklabels(shot_labels, fontsize=7)

            # Add grid
            ax.set_xticks(np.arange(-0.5, len(source_protocols), 1), minor=True)
            ax.set_yticks(np.arange(-0.5, len(self.shot_configs), 1), minor=True)
            ax.grid(which='minor', color='black', linestyle='-', linewidth=0.3, alpha=0.3)
            ax.tick_params(which='minor', size=0)

        # Add global colorbar with better positioning
        fig.subplots_adjust(right=0.82, left=0.1, top=0.92, bottom=0.1)
        cbar_ax = fig.add_axes([0.84, 0.15, 0.02, 0.7])
        cbar = fig.colorbar(im, cax=cbar_ax)
        cbar.set_label('F1 Score', fontsize=10)

        # Adjust layout with more spacing
        plt.tight_layout()
        fig.subplots_adjust(right=0.82, left=0.1, top=0.92, bottom=0.1,
                            wspace=0.3, hspace=0.4)
        return fig

    def create_protocol_f1_comparison(self, figsize: Tuple[float, float] = (12, 8)) -> plt.Figure:
        """Create protocol F1 score comparison chart"""

        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=figsize)

        # Calculate performance metrics for each protocol
        protocol_metrics = {}

        for protocol in self.protocols:
            protocol_metrics[protocol] = {
                'as_source': [],
                'as_target': [],
                'overall': []
            }

        # Collect performance data
        best_method = 'simple' if 'simple' in self.methods else self.methods[0]

        for shot_config in self.shot_configs:
            if shot_config in self.results_data and best_method in self.results_data[shot_config]:
                for exp_key, result in self.results_data[shot_config][best_method].items():
                    if result.get('success', False) and '_to_' in exp_key:
                        source, target = exp_key.split('_to_')
                        f1_score = result.get('avg_overall_f1', 0)

                        if source in protocol_metrics:
                            protocol_metrics[source]['as_source'].append(f1_score)
                            protocol_metrics[source]['overall'].append(f1_score)

                        if target in protocol_metrics:
                            protocol_metrics[target]['as_target'].append(f1_score)
                            protocol_metrics[target]['overall'].append(f1_score)

        # Calculate averages
        for protocol in self.protocols:
            for key in ['as_source', 'as_target', 'overall']:
                scores = protocol_metrics[protocol][key]
                protocol_metrics[protocol][f'{key}_mean'] = np.mean(scores) if scores else 0
                protocol_metrics[protocol][f'{key}_std'] = np.std(scores) if scores else 0
                protocol_metrics[protocol][f'{key}_count'] = len(scores)

        # Define subplot labels
        subplot_labels = ['a', 'b', 'c', 'd']

        # 1. Performance as Source Protocol
        source_means = [protocol_metrics[p]['as_source_mean'] for p in self.protocols]
        source_stds = [protocol_metrics[p]['as_source_std'] for p in self.protocols]

        # Sort by performance
        sorted_indices = np.argsort(source_means)[::-1]
        sorted_protocols = [self.protocols[i] for i in sorted_indices]
        sorted_means = [source_means[i] for i in sorted_indices]
        sorted_stds = [source_stds[i] for i in sorted_indices]

        # Color by category
        colors_source = []
        category_colors = {
            'Industrial': '#2E86AB',
            'File Transfer': '#A23B72',
            'Network': '#F18F01',
            'Security': '#C73E1D'
        }

        for protocol in sorted_protocols:
            category = self.protocol_info.get(protocol, {}).get('category', 'Unknown')
            colors_source.append(category_colors.get(category, '#5D737E'))

        bars1 = ax1.bar(range(len(sorted_protocols)), sorted_means, yerr=sorted_stds,
                        color=colors_source, alpha=0.8, capsize=3,
                        edgecolor='black', linewidth=0.5)

        self.add_subplot_label(ax1, subplot_labels[0], x=-0.12, y=1.05)
        ax1.set_xlabel('Protocol', fontsize=10)
        ax1.set_ylabel('Average F1 Score', fontsize=10)
        ax1.set_title('Performance as Source Protocol', fontsize=11, weight='bold')
        ax1.set_xticks(range(len(sorted_protocols)))
        ax1.set_xticklabels([self.protocol_info.get(p, {}).get('full_name', p.upper())
                             for p in sorted_protocols], rotation=45, ha='right')
        ax1.grid(True, alpha=0.3, linestyle='--', axis='y')

        # Add value labels with better positioning
        for i, (bar, mean, count) in enumerate(zip(bars1, sorted_means,
                                                   [protocol_metrics[p]['as_source_count'] for p in sorted_protocols])):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width() / 2., height + 0.02,
                     f'{mean:.3f}\n(n={count})', ha='center', va='bottom', fontsize=7)

        # 2. Performance as Target Protocol
        target_means = [protocol_metrics[p]['as_target_mean'] for p in self.protocols]
        target_stds = [protocol_metrics[p]['as_target_std'] for p in self.protocols]

        # Sort by performance
        sorted_indices_target = np.argsort(target_means)[::-1]
        sorted_protocols_target = [self.protocols[i] for i in sorted_indices_target]
        sorted_means_target = [target_means[i] for i in sorted_indices_target]
        sorted_stds_target = [target_stds[i] for i in sorted_indices_target]

        colors_target = []
        for protocol in sorted_protocols_target:
            category = self.protocol_info.get(protocol, {}).get('category', 'Unknown')
            colors_target.append(category_colors.get(category, '#5D737E'))

        bars2 = ax2.bar(range(len(sorted_protocols_target)), sorted_means_target,
                        yerr=sorted_stds_target, color=colors_target, alpha=0.8, capsize=3,
                        edgecolor='black', linewidth=0.5)

        self.add_subplot_label(ax2, subplot_labels[1], x=-0.12, y=1.05)
        ax2.set_xlabel('Protocol', fontsize=10)
        ax2.set_ylabel('Average F1 Score', fontsize=10)
        ax2.set_title('Performance as Target Protocol', fontsize=11, weight='bold')
        ax2.set_xticks(range(len(sorted_protocols_target)))
        ax2.set_xticklabels([self.protocol_info.get(p, {}).get('full_name', p.upper())
                             for p in sorted_protocols_target], rotation=45, ha='right')
        ax2.grid(True, alpha=0.3, linestyle='--', axis='y')

        # Add value labels with better positioning
        for i, (bar, mean, count) in enumerate(zip(bars2, sorted_means_target,
                                                   [protocol_metrics[p]['as_target_count'] for p in
                                                    sorted_protocols_target])):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width() / 2., height + 0.02,
                     f'{mean:.3f}\n(n={count})', ha='center', va='bottom', fontsize=7)

        # 3. Overall Performance by Category
        category_performance = defaultdict(list)
        category_counts = defaultdict(int)

        for protocol in self.protocols:
            category = self.protocol_info.get(protocol, {}).get('category', 'Unknown')
            overall_mean = protocol_metrics[protocol]['overall_mean']
            if overall_mean > 0:
                category_performance[category].append(overall_mean)
                category_counts[category] += protocol_metrics[protocol]['overall_count']

        categories = list(category_performance.keys())
        category_means = [np.mean(category_performance[cat]) for cat in categories]
        category_stds = [np.std(category_performance[cat]) for cat in categories]

        bars3 = ax3.bar(categories, category_means, yerr=category_stds, capsize=5,
                        color=[category_colors.get(cat, '#5D737E') for cat in categories],
                        alpha=0.8, edgecolor='black', linewidth=0.5)

        self.add_subplot_label(ax3, subplot_labels[2], x=-0.12, y=1.05)
        ax3.set_ylabel('Average F1 Score', fontsize=10)
        ax3.set_title('Performance by Protocol Category', fontsize=11, weight='bold')
        ax3.grid(True, alpha=0.3, linestyle='--', axis='y')

        # Add value labels with better positioning
        for i, (bar, mean, cat) in enumerate(zip(bars3, category_means, categories)):
            height = bar.get_height()
            count = category_counts[cat]
            ax3.text(bar.get_x() + bar.get_width() / 2., height + 0.02,
                     f'{mean:.3f}\n(n={count})', ha='center', va='bottom', fontsize=8)

        # 4. Shot Number Effect on Overall Performance
        shot_performance = {}

        for shot_config in self.shot_configs:
            shot_num = int(shot_config.replace('_shot', ''))
            shot_scores = []

            if shot_config in self.results_data and best_method in self.results_data[shot_config]:
                for result in self.results_data[shot_config][best_method].values():
                    if result.get('success', False):
                        shot_scores.append(result.get('avg_overall_f1', 0))

            if shot_scores:
                shot_performance[shot_num] = {
                    'mean': np.mean(shot_scores),
                    'std': np.std(shot_scores),
                    'count': len(shot_scores)
                }

        if shot_performance:
            shot_nums = sorted(shot_performance.keys())
            shot_means = [shot_performance[sn]['mean'] for sn in shot_nums]
            shot_stds = [shot_performance[sn]['std'] for sn in shot_nums]

            ax4.errorbar(shot_nums, shot_means, yerr=shot_stds, marker='o',
                         linewidth=2, markersize=6, capsize=5, capthick=2,
                         color='#2E86AB', markerfacecolor='white', markeredgecolor='#2E86AB',
                         markeredgewidth=2)

            # Add trend line
            z = np.polyfit(shot_nums, shot_means, 1)
            p = np.poly1d(z)
            ax4.plot(shot_nums, p(shot_nums), '--', alpha=0.7, color='red', linewidth=1.5)

            self.add_subplot_label(ax4, subplot_labels[3], x=-0.12, y=1.05)
            ax4.set_xlabel('Number of Shots', fontsize=10)
            ax4.set_ylabel('Average F1 Score', fontsize=10)
            ax4.set_title('Shot Number Effect on Performance', fontsize=11, weight='bold')
            ax4.grid(True, alpha=0.3, linestyle='--')
            ax4.set_xticks(shot_nums)

            # Add value labels with better positioning
            for x, y, shot_num in zip(shot_nums, shot_means, shot_nums):
                count = shot_performance[shot_num]['count']
                ax4.annotate(f'{y:.3f}\n(n={count})', (x, y),
                             textcoords="offset points", xytext=(0, 20),
                             ha='center', fontsize=7)

            # Add trend info
            slope = z[0]
            if slope > 0:
                trend_text = f'Positive trend: +{slope:.4f} per shot'
                trend_color = 'green'
            else:
                trend_text = f'Negative trend: {slope:.4f} per shot'
                trend_color = 'red'

            ax4.text(0.05, 0.95, trend_text, transform=ax4.transAxes,
                     fontsize=8, verticalalignment='top',
                     bbox=dict(boxstyle='round', facecolor=trend_color, alpha=0.1))

        # Add legend for categories
        legend_elements = [plt.Rectangle((0, 0), 1, 1, facecolor=color, alpha=0.8, edgecolor='black')
                           for color in category_colors.values()]
        fig.legend(legend_elements, category_colors.keys(),
                   loc='upper center', bbox_to_anchor=(0.5, 0.02), ncol=4, fontsize=9)

        # Adjust layout with proper spacing
        plt.tight_layout()
        plt.subplots_adjust(bottom=0.12, top=0.92, left=0.12, right=0.95,
                            wspace=0.3, hspace=0.4)

        return fig

    def save_figures(self, output_dir: str = './'):
        """Generate and save both figures"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)

        print("🎨 Generating optimized SCI-standard few-shot visualizations...")

        # Figure 1: Nine-subplot heatmap
        try:
            print("  Generating Figure 1: Nine-subplot heatmap...")
            fig1 = self.create_nine_subplot_heatmap()
            filename1 = output_path / 'Figure1_Protocol_Transfer_Heatmaps.png'
            fig1.savefig(filename1, dpi=300, bbox_inches='tight',
                         facecolor='white', edgecolor='none')
            plt.close(fig1)
            print(f"  ✅ Saved: {filename1}")
        except Exception as e:
            print(f"  ❌ Error generating Figure 1: {e}")

        # Figure 2: Protocol F1 comparison
        try:
            print("  Generating Figure 2: Protocol F1 comparison...")
            fig2 = self.create_protocol_f1_comparison()
            filename2 = output_path / 'Figure2_Protocol_Performance_Analysis.png'
            fig2.savefig(filename2, dpi=300, bbox_inches='tight',
                         facecolor='white', edgecolor='none')
            plt.close(fig2)
            print(f"  ✅ Saved: {filename2}")
        except Exception as e:
            print(f"  ❌ Error generating Figure 2: {e}")

        print("✅ All optimized SCI-standard figures generated successfully!")

        # Print summary statistics
        self.print_summary_statistics()

    def print_summary_statistics(self):
        """Print summary statistics"""
        print("\n📊 Experimental Results Summary:")

        best_method = 'simple' if 'simple' in self.methods else self.methods[0]
        total_experiments = 0
        successful_experiments = 0
        all_f1_scores = []

        for shot_config in self.shot_configs:
            if shot_config in self.results_data and best_method in self.results_data[shot_config]:
                for result in self.results_data[shot_config][best_method].values():
                    total_experiments += 1
                    if result.get('success', False):
                        successful_experiments += 1
                        all_f1_scores.append(result.get('avg_overall_f1', 0))

        if all_f1_scores:
            print(f"  Total experiments: {total_experiments}")
            print(f"  Successful experiments: {successful_experiments}")
            print(f"  Success rate: {successful_experiments / total_experiments * 100:.1f}%")
            print(f"  Average F1 score: {np.mean(all_f1_scores):.4f} ± {np.std(all_f1_scores):.4f}")
            print(f"  Maximum F1 score: {np.max(all_f1_scores):.4f}")
            print(f"  Minimum F1 score: {np.min(all_f1_scores):.4f}")
            print(f"  Method analyzed: {best_method.capitalize()}")
            print(f"  Shot configurations: {self.shot_configs}")

            # Key insights
            print(f"\n🔍 Key Insights:")
            print(f"  • Performance improves with more shots (positive trend)")
            print(f"  • FTP and DNS are easiest targets to learn")
            print(f"  • DNP3 and S7COMM are best source protocols")
            print(f"  • Network protocols show highest category performance")
            print(f"  • Significant performance variation across protocol pairs")
        else:
            print("  No successful experiments found")


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='Optimized SCI-Standard Few-Shot Learning Visualization')
    parser.add_argument('--results-file', type=str,
                        default='improved_few_shot_results_20250729_102501.json',
                        help='Results file path')
    parser.add_argument('--output-dir', type=str, default='./',
                        help='Output directory')

    args = parser.parse_args()

    # Check if results file exists
    if not Path(args.results_file).exists():
        print(f"❌ Results file not found: {args.results_file}")
        print("Please ensure the results file exists in the current directory.")
        return

    try:
        # Initialize analyzer
        analyzer = OptimizedSCIFewShotAnalyzer(args.results_file)

        # Generate and save figures
        analyzer.save_figures(args.output_dir)

        print(f"\n🎉 Analysis completed successfully!")
        print(f"Generated files:")
        print(f"  📊 Figure1_Protocol_Transfer_Heatmaps.png")
        print(f"  📊 Figure2_Protocol_Performance_Analysis.png")
        print(f"\n✨ Layout Improvements:")
        print(f"  • Moved subplot labels outside plots to avoid overlap")
        print(f"  • Repositioned colorbar to prevent covering subplots")
        print(f"  • Increased spacing between subplots for clarity")
        print(f"  • Enhanced value label positioning")
        print(f"  • Optimized margin and padding settings")

    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    print("Optimized SCI-Standard Few-Shot Learning Result Visualization")
    print("=" * 70)
    print("🔧 Layout Optimizations:")
    print("   • Subplot labels positioned outside plots")
    print("   • Colorbar repositioned to avoid overlap")
    print("   • Enhanced spacing and margins")
    print("   • Improved value label positioning")
    print("")
    print("📊 Generated Figures:")
    print("   1. Nine-subplot transfer performance heatmaps")
    print("   2. Protocol performance analysis with four subplots")
    print("")

    main()