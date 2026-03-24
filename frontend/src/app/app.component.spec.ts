import { TestBed } from '@angular/core/testing';
import { AppComponent } from './app.component';

// Basic unit tests for the root AppComponent to ensure it initializes correctly and renders expected content.
describe('AppComponent', () => {
  beforeEach(async () => {
    // Configure a testing module that declares/imports the standalone AppComponent.
    await TestBed.configureTestingModule({
      imports: [AppComponent]
    }).compileComponents();
  });

  it('should create the app', () => {
    // Sanity check that the root component instantiates without throwing.
    const fixture = TestBed.createComponent(AppComponent);
    const app = fixture.componentInstance;
    expect(app).toBeTruthy();
  });

  it(`should have the 'frontend' title`, () => {
    // Verifies that the component's title property matches our expected string.
    const fixture = TestBed.createComponent(AppComponent);
    const app = fixture.componentInstance;
    expect(app.title).toEqual('frontend');
  });

  it('should render title', () => {
    // Ensures the template actually renders the title text in the DOM.
    const fixture = TestBed.createComponent(AppComponent);
    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('h1')?.textContent).toContain('Hello, frontend');
  });
});
