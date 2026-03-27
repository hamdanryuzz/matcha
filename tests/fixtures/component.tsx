export function ProfileCard({ bioHtml }: { bioHtml: string }) {
  return (
    <section>
      <div dangerouslySetInnerHTML={{ __html: bioHtml }} />
    </section>
  );
}
