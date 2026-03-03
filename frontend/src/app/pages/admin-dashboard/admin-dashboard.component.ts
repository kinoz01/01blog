import { CommonModule } from '@angular/common';
import { Component, HostListener, OnInit, inject } from '@angular/core';
import { RouterLink } from '@angular/router';

import { ReportSummary } from '../../core/models/report.models';
import { AdminService } from '../../core/services/admin.service';
import { Observable, forkJoin } from 'rxjs';
import { AdminUser } from '../../core/models/admin.models';
import { Post } from '../../core/models/post.models';

@Component({
  selector: 'app-admin-dashboard',
  standalone: true,
  imports: [CommonModule, RouterLink],
  templateUrl: './admin-dashboard.component.html',
  styleUrl: './admin-dashboard.component.scss'
})
export class AdminDashboardComponent implements OnInit {
  
}
