Return-Path: <kasan-dev+bncBCS5D2F7IUINLX6TZADBUBCKWZ7BK@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id D6C00C5479F
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Nov 2025 21:36:39 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-5957ecd65c8sf61729e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Nov 2025 12:36:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762979799; cv=pass;
        d=google.com; s=arc-20240605;
        b=kZ+bjEFH3MNn+WZWKYxPJH/B6W+ImEPgSFFez6cnhvwxi3Xt0hn/cMul3Wne2lkC8z
         IyImRGdXPGID8ANXn1Nwe0SN9C64E92w0XI2jqyUaT3oOW+21zJGOQrkLgNu7wy946ju
         9LSxgYuc7vBR6eVSWjtjUg6hdPDlVfe+8JDkUvZL6SVenLsBTiZLUye+rQNMF5acW9Wo
         Igxy9zJEpow2J7dHrGDwrbqeIo03O+J+dWA8pnOZpiqC7t/BMocc69QHrd03FP78Udz8
         kUFVojiIuCuG9oaWgMaQbqUybTjpDy//74H5LB+OwOUsa1bo6RxRrIPtxQrB+jrfF4JK
         qxaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=byOUVbPJf8LE2BfPxDK8V10G8kcDlIgZlV5EjFuhor0=;
        fh=VRfbqi3zShyHoHRbNo99/MMaozs2hJ+KxbW+8A0aAkY=;
        b=RGCCNTF1+0m5QQGBPb8h6QZTR2yr8cWi1nI4kSmpvQ+1dk+LlMmxV/IJSl1yKcqxzR
         xvfBcaFy5D/DYXZow/rOCqyPNY4yLCr7SqDF26X0BRHxvPEVwz3Tl5A64NzgBgzJUyCK
         hKyLA69MteIBGJoE8Mr6b1TrEOe4Y1jCYbYcBL6VFRBpuLh68Ehl4OUdRtmfbrU6pbfl
         jszZquNLE+XrSkeql7vgRNNgWqxUnzdEvri+1ClGl0JUqyEGzVlGpnAkJWpfUf98DAmW
         t2iEcBtXNE5oKIa5uUoYGLPVfPzZnbYhFlB0LQlXQHy0XSzZOWtCPy0I91WH2ZhmQuy4
         MgOw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=kp57rjur;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762979799; x=1763584599; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=byOUVbPJf8LE2BfPxDK8V10G8kcDlIgZlV5EjFuhor0=;
        b=dp1CrsGFcMe8TlXOfVgfSM/mPKb005YX4/0tTvLn1jl21j9yPA+FalL7j5v2FZBT7e
         WOUSLwVmA8EmWGQpuIfnKXoTc/VZpgw1eT7QoSxdZl5LeCl01mEIYNV1GMMwDyn6nYIN
         +3Mpcwcr6DOwFwaXTwciUS/R4c4hqSZXXrvdRUneBv+o31Kil5YVJB06P/WwrC7gp2rI
         fyVZ0rhgf1UkyO8hlNqPRjum4Dn0KW1SFexgNJR0BOJLEx0fpyYUOjnb2W1zpHBumEe2
         Ly3t/2+VOQvIa231NsQGNA6vC66CvVQ0j2tDsnsocmkGDMKIs0ngE2ErI4nDt2Nme6eP
         H++g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762979799; x=1763584599;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=byOUVbPJf8LE2BfPxDK8V10G8kcDlIgZlV5EjFuhor0=;
        b=VGu7Be9P2rNqsr17fpAHMYqfVqLzhOvlMBOuXNNgjONB/R6/xXw1zm2K+2Netxhw9P
         LvNjNHD1JOceJG51LcGabVGESEk8ZUtlc1eVNxt5WuTyIz007OEQ5mKX6zajZmt/Tfrg
         TPmWud0MpSM/JxDhSDQ6AxriAUzkUvMIbqm8o7rN0B7DpaM/gu/ViXR3CL209xrTn/Po
         B0ngVIQFi7xZP4HaXO0gRcp5oiZhotuHorkpJJGx16xJpNV7IiTJ2kn+agniMOMXgThi
         UnAJrJrVkxhSKn3RafCNPGTnYWp4Czk8V9H3onzXHEcpau43HRZ/WYKbgQX7nzcMlbu2
         N8jg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUcK2wFmjycYrGavB8ze0P2iEcO5C6Dvta2nBv3Oel/E2vP10Mrai0lYW4QAcf8RiZC0jzwhg==@lfdr.de
X-Gm-Message-State: AOJu0YwGS25jNaROri7a3vWi5H/m1VohyOCDXhtVESOqKrOIstbhZ0XE
	Osh/LTJYaf62XRcyo4S+hjtPzIEztsG2eo9P78+6Dn4EUKO297Sg0rD7
X-Google-Smtp-Source: AGHT+IEmUWInt5F6kBcc3/8r+b6VcVeXmuSkyjNm5r94LGheuRvHsVJfOoMGJsk6X1n1+0/a9YTn5Q==
X-Received: by 2002:a05:6512:4017:b0:594:2d64:bd03 with SMTP id 2adb3069b0e04-59576df3237mr1274567e87.1.1762979798542;
        Wed, 12 Nov 2025 12:36:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Y2B13ww8eH3kRkICrlQVmYDV20x2GLZCQuyJaqAmPvIw=="
Received: by 2002:a05:6512:6185:b0:594:6100:803a with SMTP id
 2adb3069b0e04-5957ed18788ls128342e87.1.-pod-prod-08-eu; Wed, 12 Nov 2025
 12:36:35 -0800 (PST)
X-Received: by 2002:a05:6512:24d8:10b0:595:7c57:e0b2 with SMTP id 2adb3069b0e04-5957c57e295mr793828e87.49.1762979795114;
        Wed, 12 Nov 2025 12:36:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762979795; cv=none;
        d=google.com; s=arc-20240605;
        b=hIpp/cDG8/HGjkUFD2YehsKbbwXb2rWoNb7q0psi1FpmK8EEQEp8FQUUXg53ELWCEd
         1xz3Q2kIGR+AFOuIrF99a7Ohgm5n7XslLWSSLpY8SEVOi6k+ZNEwZ4zqrWHwUK9p5B8N
         hF8Xse1XTW/2HMp4HqW4HPfSTVAUKQyX3ySOEx1Zur30Z2Tjl026XDm17wJPEtlJ0J+5
         +axkgZl/tWmBmJsGqJCwnmgq7T9lcuEpaqI4L7A93BR3Kg1ywMQfwJK+gTkIp9QetcjQ
         jZ9D8N4v3VAyZ4JME3KLSfzsHRcxmQ299OQo3oYs/njC6lEkZJYT14rdjMmJuH7NiOYZ
         7HLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=s9o8NRvJdzTieC05I6sj+VphdIDRCWgXCmaEd+EQUzE=;
        fh=tg/ztlCF060OpLC1muJc3FOu1Jx8mcVuMVMQ6bKF25I=;
        b=SABI5Pug892+/NWM211YUfpAmQH8pIhjn56VKa9/1a+ILMa25zMvrYwyN2ET3wQhwo
         20n4nj3JXnq695griKqmtm/m02A5S+Pw/temmDnDH7AV0RqUDtbEENdh+u2/3k2iCbT3
         CG9+e8YCe0K518AteJKMe5nXKlMBqa7wzCGOxZvgld10SQjVP2y+baMkD83wrVtAs/dx
         SgE+mOWr2oQlGSTOVe3vAzk0RXv64B/JHYmbJ8i/ZEk1zLFvoYe/KqFa4I6o5s7vbXr7
         3x8oN1BxvuEi/580NiRWlbILQZc3l0sQJY0Sr/Mk2QLpWW9lQIUmuLy3TSTxTQusZ3S9
         yigA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=kp57rjur;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37b9cb7e438si1541fa.0.2025.11.12.12.36.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Nov 2025 12:36:35 -0800 (PST)
Received-SPF: none (google.com: willy@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vJHZx-00000006TTz-1U22;
	Wed, 12 Nov 2025 20:36:33 +0000
Date: Wed, 12 Nov 2025 20:36:33 +0000
From: Matthew Wilcox <willy@infradead.org>
To: Jinchao Wang <wangjinchao600@gmail.com>
Cc: kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-perf-users@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org, llvm@lists.linux.dev,
	workflows@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v8 00/27] mm/ksw: Introduce KStackWatch debugging tool
Message-ID: <aRTv0eHfX0j8vJOW@casper.infradead.org>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
 <aRIh4pBs7KCDhQOp@casper.infradead.org>
 <aRLmGxKVvfl5N792@ndev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <aRLmGxKVvfl5N792@ndev>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=kp57rjur;
       spf=none (google.com: willy@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=willy@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

[dropping all the individual email addresses; leaving only the
mailing lists]

On Wed, Nov 12, 2025 at 10:14:29AM +0800, Jinchao Wang wrote:
> On Mon, Nov 10, 2025 at 05:33:22PM +0000, Matthew Wilcox wrote:
> > On Tue, Nov 11, 2025 at 12:35:55AM +0800, Jinchao Wang wrote:
> > > Earlier this year, I debugged a stack corruption panic that revealed =
the
> > > limitations of existing debugging tools. The bug persisted for 739 da=
ys
> > > before being fixed (CVE-2025-22036), and my reproduction scenario
> > > differed from the CVE report=E2=80=94highlighting how unpredictably t=
hese bugs
> > > manifest.
> >=20
> > Well, this demonstrates the dangers of keeping this problem siloed
> > within your own exfat group.  The fix made in 1bb7ff4204b6 is wrong!
> > It was fixed properly in 7375f22495e7 which lists its Fixes: as
> > Linux-2.6.12-rc2, but that's simply the beginning of git history.
> > It's actually been there since v2.4.6.4 where it's documented as simply=
:
> >=20
> >       - some subtle fs/buffer.c race conditions (Andrew Morton, me)
> >=20
> > As far as I can tell the changes made in 1bb7ff4204b6 should be
> > reverted.
>=20
> Thank you for the correction and the detailed history. I wasn't aware thi=
s
> dated back to v2.4.6.4. I'm not part of the exfat group; I simply
> encountered a bug that 1bb7ff4204b6 happened to resolve in my scenario.
> The timeline actually illustrates the exact problem KStackWatch addresses=
:
> a bug introduced in 2001, partially addressed in 2025, then properly fixe=
d
> months later. The 24-year gap suggests these silent stack corruptions are
> extremely difficult to locate.

I think that's a misdiagnosis caused by not understanding the limited
circumstances in which the problem occurs.  To hit this problem, you
have to have a buffer_head allocated on the stack.  That doesn't happen
in many places:

fs/buffer.c:    struct buffer_head tmp =3D {
fs/direct-io.c: struct buffer_head map_bh =3D { 0, };
fs/ext2/super.c:        struct buffer_head tmp_bh;
fs/ext2/super.c:        struct buffer_head tmp_bh;
fs/ext4/mballoc-test.c: struct buffer_head bitmap_bh;
fs/ext4/mballoc-test.c: struct buffer_head gd_bh;
fs/gfs2/bmap.c: struct buffer_head bh;
fs/gfs2/bmap.c: struct buffer_head bh;
fs/isofs/inode.c:       struct buffer_head dummy;
fs/jfs/super.c: struct buffer_head tmp_bh;
fs/jfs/super.c: struct buffer_head tmp_bh;
fs/mpage.c:     struct buffer_head map_bh;
fs/mpage.c:     struct buffer_head map_bh;

It's far more common for buffer_heads to be allocated from slab and
attached to folios.  The other necessary condition to hit this problem
is that get_block() has to actually read the data from disk.  That's
not normal either!  Most filesystems just fill in the metadata about
the block and defer the actual read to when the data is wanted.  That's
the high-performance way to do it.

So our opportunity to catch this bug was highly limited by the fact that
we just don't run the codepaths that would allow it to trigger.

> > > Initially, I enabled KASAN, but the bug did not reproduce. Reviewing =
the
> > > code in __blk_flush_plug(), I found it difficult to trace all logic
> > > paths due to indirect function calls through function pointers.
> >=20
> > So why is the solution here not simply to fix KASAN instead of this
> > giant patch series?
>=20
> KASAN caught 7375f22495e7 because put_bh() accessed bh->b_count after
> wait_on_buffer() of another thread returned=E2=80=94the stack was invalid=
.
> In 1bb7ff4204b6 and my case, corruption occurred before the victim
> function of another thread returned. The stack remained valid to KASAN,
> so no warning triggered. This is timing-dependent, not a KASAN deficiency=
.

I agree that it's a narrow race window, but nevertheless KASAN did catch
it with ntfs and not with exfat.  The KASAN documentation states that
it can catch this kind of bug:

Generic KASAN supports finding bugs in all of slab, page_alloc, vmap, vmall=
oc,
stack, and global memory.

Software Tag-Based KASAN supports slab, page_alloc, vmalloc, and stack memo=
ry.

Hardware Tag-Based KASAN supports slab, page_alloc, and non-executable vmal=
loc
memory.

(hm, were you using hwkasan instead of swkasan, and that's why you
couldn't see it?)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
RTv0eHfX0j8vJOW%40casper.infradead.org.
