import { CommonModule } from '@angular/common';
import { Component, HostListener, OnDestroy, OnInit, inject } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Subject, catchError, of, switchMap, takeUntil } from 'rxjs';

import { Post, PostMedia } from '../../core/models/post.models';
import { UserProfileDetails } from '../../core/models/user.models';
import { UserService } from '../../core/services/user.service';
import { PostService } from '../../core/services/post.service';
import { AuthService } from '../../core/services/auth.service';
import { ReportService } from '../../core/services/report.service';

interface MediaPreview {
  file: File;
  previewUrl: string;
  kind: 'image' | 'video';
}

interface EditableMedia extends PostMedia {
  markedForRemoval: boolean;
}

@Component({
  selector: 'app-user-profile',
  standalone: true,
  imports: [CommonModule, RouterLink, ReactiveFormsModule],
  templateUrl: './user-profile.component.html',
  styleUrl: './user-profile.component.scss'
})
export class UserProfileComponent implements OnDestroy, OnInit {
  
}
