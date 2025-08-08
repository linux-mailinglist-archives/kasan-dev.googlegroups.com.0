Return-Path: <kasan-dev+bncBCKPFB7SXUERBLHH27CAMGQEHLU6IWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FD68B1E8AC
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 14:55:10 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 41be03b00d2f7-b3f33295703sf3182560a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Aug 2025 05:55:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754657708; cv=pass;
        d=google.com; s=arc-20240605;
        b=UB93c+Wtt1QktHusWTBYUDGv6ZXXR2HxO8mIdekCe+PBAzuo7jPnsyreVYcyrT8oO8
         svSu77mPL1IF7YPmfPfQ0lFBDjzliLlRygMG2XI1Z6FLSpM55EihwDhr074y+L1D0U5w
         VVXWDM3Rs5P/mCuFr1ZEsKkql6X8OvcQIe8yXgRKYHJN2Oc2RgpU0G0D6PbUJbOE8tMG
         KoDTSoSw5lFK/EwJyXPU40aJC/r35LAWZA4hsCQ2oLoTbeoW3dU8LNFDnMOn1zB2Pn3x
         wf6vLoHhCfyahVzE6ky/Z10LgdOlrGh+JT8pqjvojwRQaEWlvdBMfwO1sgNRGmIHOxfv
         ELPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=WmXgjoDAJ3VUBV4CWKcIEYgy9K3VL7DXgddqtyoSYbg=;
        fh=Qy3VyWzZcsHusyzx9gCZleYI+FnsqIgCRhbIhubnMGA=;
        b=V81KkskVBDdq7jvebU0PTr/WceJCDXK4aspFlwmowEmzU+h929hNUiCDZKxEDHJ6/C
         +wledVTfsFpmDSx88gwbqQb3WSXApcH8SS15Dw3oKfjwdnHAvAE2vCuYUtGie49XyfTx
         zul7m6rXl+hSf58fR/QTcLC59B7CiMSDJZk4Gmx3D4Rub3ZHppd5RSF8uvOS4MJ2VU3S
         8mSvCEFntsbH7S+7jkI3rkBjbESg6g69g7neeTmvXTVOSMeUnAdkejdbYCn7j0hSEzaw
         Wf5p3+pc13T6pw7i/xz8Pu6aMDIlVSxswFpUmOlDxzG45GKeYtcAWOe3mFpqBo35doVe
         TvCA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RD7hn96s;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754657708; x=1755262508; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=WmXgjoDAJ3VUBV4CWKcIEYgy9K3VL7DXgddqtyoSYbg=;
        b=Xl902X2K2C5HO/PKlyHBr/G24aW/wtVesttmDWspFhihIr4yAf6Yhmoj/c0GmbCRvC
         CIOFJLTzrGVHmczh3lQiucNwYhP3pJsWk6/pRMiaPec4ZSp7v5EOKE2bvg78kXhhkfYO
         grMFN7rE1p5nc9DVkjab8B9wrBxbhsnTlsGZFpI5ENm/PJyLoCYnFdGLMVEoamBY+1IY
         OSlhMduZWPQ3B8AHHc8A637Yv+RMZ+6sSX4pG+XPL61O/LRbjCdB2M29ek2takybG3cz
         FpuhGu6uCheYXdMF/wBzIdg03ng+r8U2+mw6fcCaFv4dbjSe/ozrKW4HycFO6QOQPDMB
         69SQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754657708; x=1755262508;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WmXgjoDAJ3VUBV4CWKcIEYgy9K3VL7DXgddqtyoSYbg=;
        b=OSx6qwqYzhqVUKMqhswkpOmt1GYZYlrqZQzEKo/FKWUuJvZfdqmamLP2icZ5s8866f
         M7D/r3/RrLkPvcCVYAMw48LGwPjofgfAZZ9hNiMCieCa735E+LDBI06St1EkCcVLDP7z
         p2gUAo9WKZQZ3ruO0wXJhtqSFlv//r9zHkjHksDrTrhCgvK0lgfQGJTv4TcEaZ0sovgT
         h7KxxJpL4zuTIlgs1+2WbhCrK3lhKZGA95hmsBtdSxy3en/cOdpnN8FFlT2C1r1pTDCm
         OQujGQqyX3YUIKZ2fBUAtOtd0op0/rj+8mdoBM+7hE8brCnsPqnrLHyXb3kiaDHPCYQG
         c3tQ==
X-Forwarded-Encrypted: i=2; AJvYcCXdNTSSg8h2zOjTfg/ZzeAYthEOQYs51OmHjiGRhHLYfRTyQOC8luX4zzb6aHiWCKTLhK0feg==@lfdr.de
X-Gm-Message-State: AOJu0YxlzDy7l1+sDVK2zkOS3v3wPOzeCRUg8BK7shfwhvpVh3Ybsup+
	u4vChhOSfVSML/86N2wt3CnbqkOHvzuqfWNqTCsT2iSeuawPCREb+yGA
X-Google-Smtp-Source: AGHT+IEJWpfHb8a8/zr1Q0EOr+dqY6vN5nByHb8u+Ra7UpthUTbZ9yK0O//DsHzXlF0Z4FpD6T+g+A==
X-Received: by 2002:a17:902:d585:b0:235:e9fe:83c0 with SMTP id d9443c01a7336-242c21de2bcmr39045225ad.27.1754657708476;
        Fri, 08 Aug 2025 05:55:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe8bNADsT9W5fmorROrG3QhA/+/B2t6670K+0bD0pJvmw==
Received: by 2002:a17:903:1106:b0:237:f1a3:b13b with SMTP id
 d9443c01a7336-242afd14152ls29557465ad.2.-pod-prod-03-us; Fri, 08 Aug 2025
 05:55:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV2nKPre4gb486Bqo+FJJMFulVS9r/ZbJC21dCGXqHFF8R0kQ2FbLIJeQZKJrCTn5hWfXFrgQb2fn8=@googlegroups.com
X-Received: by 2002:a17:903:1c2:b0:240:a889:554d with SMTP id d9443c01a7336-242c22299femr43473555ad.45.1754657706955;
        Fri, 08 Aug 2025 05:55:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754657706; cv=none;
        d=google.com; s=arc-20240605;
        b=R5bZvealspTDmIAky7c+0TPEfuG3IFYsRcOZVVdhNk157sTGzSm0bUpW6nZyc4DwO4
         UGU/FkGBEWkv4JynYNu3MnXa02VJWFVqX7syIOfa3or0Nvx3Lm75Nbm251SOCP7CbzLB
         crwtTl4kY8TolgrY+k/EST8jCB4MUA233XcHMvNq48X79jh2Pg/9GmQRBlicdVi1wk+R
         yLcM1sQJJLIKybh6+RBJrPbT3rlwtAoZu863jGhIVyuGWOtveH8hhwFT0pO6ip5Qm7xv
         hkU/PSJoSSxg1koThv/trseCalL6mkdb+EVTQjfTWwdfdWSu6JgWQ4EZkNoQoPTQoux4
         bDgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=735MKqTpVsLiwF08r9eYm/WhPdFnfobFmT9GhcsZRXQ=;
        fh=2cxiwXYQyp5Mt4TMi4cYhH8Jkzsf6cjELONDx+KhRfE=;
        b=lUDAPxux9XRqhVkxnnpjMqF9BTSDhOD7WBLELoBGtlss95ylCQm4bJOiXsOPTDak8r
         MhDHvoBP/WXJS8HrRuTpA7oOM37F8A0/UTmrkkpTpeUQnVlZ85vtbn/vTRw7ZM6K2x1q
         njYXw08oClC6NE9mO5ivSPoQoqnajk5pKFm7gHMU9ShiW+ITfyBO8PPGsl9LY6qcSciQ
         0UFvlJcFTbcq1YcFJXP6JZKosaKcI1qoM3JktePbh1g0MzXtubavr4Gx+bierev5xhV8
         hIbk3GWMTCeWwQm2aI6fX/0G1+snxPraGGdIfOMxYbm0/e6iMvQCcpdJCs/hSdAkJsFx
         yieA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RD7hn96s;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241e8941331si8721085ad.8.2025.08.08.05.55.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Aug 2025 05:55:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-686-JSQNINiVOQuzqBr7vxM5Mg-1; Fri,
 08 Aug 2025 08:55:02 -0400
X-MC-Unique: JSQNINiVOQuzqBr7vxM5Mg-1
X-Mimecast-MFC-AGG-ID: JSQNINiVOQuzqBr7vxM5Mg_1754657700
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 5804B180036E;
	Fri,  8 Aug 2025 12:55:00 +0000 (UTC)
Received: from localhost (unknown [10.72.112.126])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id A3F3B180047F;
	Fri,  8 Aug 2025 12:54:57 +0000 (UTC)
Date: Fri, 8 Aug 2025 20:54:53 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: linux-mm@kvack.org, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org
Subject: Re: [PATCH 0/4] mm/kasan: make kasan=on|off work for all three modes
Message-ID: <aJXznYlO7dpY+p7D@MiWiFi-R3L-srv>
References: <20250805062333.121553-1-bhe@redhat.com>
 <69b4f07d-b83d-4ead-b3f1-1e42b2dca9c2@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <69b4f07d-b83d-4ead-b3f1-1e42b2dca9c2@gmail.com>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=RD7hn96s;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

On 08/07/25 at 06:34pm, Andrey Ryabinin wrote:
> 
> 
> On 8/5/25 8:23 AM, Baoquan He wrote:
> > Currently only hw_tags mode of kasan can be enabled or disabled with
> > kernel parameter kasan=on|off for built kernel. For kasan generic and
> > sw_tags mode, there's no way to disable them once kernel is built. 
> > This is not convenient sometime, e.g in system kdump is configured.
> > When the 1st kernel has KASAN enabled and crash triggered to switch to
> > kdump kernel, the generic or sw_tags mode will cost much extra memory
> > for kasan shadow while in fact it's meaningless to have kasan in kdump
> > kernel.
> > 
> 
> Ideally this problem should be solved by having kdump kernel with different
> config. Because if we want only reliably collect crash dumps, than we probably
> don't want other debug features, e.g. like VM_BUG_ON() crashing our kdump kernel.

Yeah, we have done that in Redhat's internal CI testing. While we still
want to switch back to let kdump take the same kernel as the 1st kernel.
Like this, we have chance to test debug kernel for vmcore dumping. In
this case, KASAN is the main barrier. For other debug features,
VM_BUG_ON() should be captured in 1st kernel's running, we won't wait to
run kdump kernel to catch it. I am planning to check and adding feature
switch for kdump to disable if it's not needed in kdump kernel. E.g I
have done in ima=on|off, and the existing 'kfence.sample_interval=0' for
kfence.

And the public kasan=on|off kernel parameter can make kasan feature more
flexible. It can be used in production environment with kasan=off, and
can switch to the same kernel to catch issues easily by stripping the
cmdline setting. As adding a cmdline is much easier than setting kernel
config and rebuild kernel.

Besides, based on this patchset, we can easily remove
kasan_arch_is_ready() by detecting the arch's support and disable
kasan_flag_enabled. And when I testing generic/sw_tags/hw_tags on arm64,
I feel if adding a kernel parameter for choosing different KASAN mode is
much more convenient than changing kernel config and rebuild. If we
choose to KASAN_OUTLINE, this even doesn't impact much in production
environment. I would like to hear your suggestion.

Thanks
Baoquan
> 
> 
> > So this patchset moves the kasan=on|off out of hw_tags scope and into
> > common code to make it visible in generic and sw_tags mode too. Then we
> > can add kasan=off in kdump kernel to reduce the unneeded meomry cost for
> > kasan.
> > 
> > Test:
> > =====
> > I only took test on x86_64 for generic mode, and on arm64 for
> > generic, sw_tags and hw_tags mode. All of them works well.
> > 
> > However when I tested sw_tags on a HPE apollo arm64 machine, it always
> > breaks kernel with a KASAN bug. Even w/o this patchset applied, the bug 
> > can always be seen too.
> > 
> > "BUG: KASAN: invalid-access in pcpu_alloc_noprof+0x42c/0x9a8"
> > 
> > I haven't got root cause of the bug, will report the bug later in
> > another thread.
> > ====
> > 
> > Baoquan He (4):
> >   mm/kasan: add conditional checks in functions to return directly if
> >     kasan is disabled
> >   mm/kasan: move kasan= code to common place
> >   mm/kasan: don't initialize kasan if it's disabled
> >   mm/kasan: make kasan=on|off take effect for all three modes
> > 
> >  arch/arm/mm/kasan_init.c               |  6 +++++
> >  arch/arm64/mm/kasan_init.c             |  7 ++++++
> >  arch/loongarch/mm/kasan_init.c         |  5 ++++
> >  arch/powerpc/mm/kasan/init_32.c        |  8 +++++-
> >  arch/powerpc/mm/kasan/init_book3e_64.c |  6 +++++
> >  arch/powerpc/mm/kasan/init_book3s_64.c |  6 +++++
> >  arch/riscv/mm/kasan_init.c             |  6 +++++
> >  arch/um/kernel/mem.c                   |  6 +++++
> >  arch/x86/mm/kasan_init_64.c            |  6 +++++
> >  arch/xtensa/mm/kasan_init.c            |  6 +++++
> >  include/linux/kasan-enabled.h          | 11 ++------
> >  mm/kasan/common.c                      | 27 ++++++++++++++++++++
> >  mm/kasan/generic.c                     | 20 +++++++++++++--
> >  mm/kasan/hw_tags.c                     | 35 ++------------------------
> >  mm/kasan/init.c                        |  6 +++++
> >  mm/kasan/quarantine.c                  |  3 +++
> >  mm/kasan/shadow.c                      | 23 ++++++++++++++++-
> >  mm/kasan/sw_tags.c                     |  9 +++++++
> >  18 files changed, 150 insertions(+), 46 deletions(-)
> > 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJXznYlO7dpY%2Bp7D%40MiWiFi-R3L-srv.
