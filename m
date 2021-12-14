Return-Path: <kasan-dev+bncBCKJJ7XLVUBBB26Y4KGQMGQEQ3MXRUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 34EE4474549
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 15:38:37 +0100 (CET)
Received: by mail-qk1-x740.google.com with SMTP id de12-20020a05620a370c00b00467697ab8a7sf17030401qkb.9
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 06:38:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639492716; cv=pass;
        d=google.com; s=arc-20160816;
        b=wAmtn9sGDy9NKMoVyYWMRKaqcS06EHWBSiADyAEJCh8Nz6SPP9gk3KtpPniMxzkKA+
         Iq9mJ94R2JGB9yjdoYcVbSUWRIL4kXbnXlPI4458JUqauHOHXT7/YRiWZMGmWquz18gy
         ae6oJCFibhbpROdpvot3mJiQa1vf1D/5jUSKSnk3hR3eQDCGxQzf9WOG6Zt/V9QIOXLO
         wBZYWZiJh3585PArnkBx0FdaBo/EuSlKGEWRIc9sPDTSuL4flgPfHVyg1ZL//z+vTl8C
         Pum6Yj/UVBcUt9l2gB67brErCSRF2Q5MyB7qALqVtKdQWng04QnsZGrN11rBIa37bU9f
         1otA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=Xh/fiPeIkvg7PVPc5LqRTGtpoHE5WiNwGXd2jqITvAM=;
        b=W7lKl91aqcDvHNihhrpAO7gdnKI+vlShcqhn5ayi9dJ8c/yEudgWf/lwQtL129NRti
         TnYDfulmUsWMWAgnkb4WGkgoD0Q5NgFCiq8VhzB8f50U3YZ5K2IVoNTD2rtSit4WGfho
         pfigY5xAM1A2/zN1WoGzGztdFh0/YHTCYO7GpjgUeX6whf7LC0BKkrVUWnCbTckvj9O8
         cp4YNHQINPmE8JFa02yPL+vBKA7KIR2Ecawa2LvtwT7OD47USX8MSafIIo8u76zDHl35
         phRCpEgpVzRFUacggL7y6rFFlCsWYd4MUSpqSGoTYwq9D0A+nQ8OjcOWeQo7FTpxnb4o
         FYdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GOrcD4Bm;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Xh/fiPeIkvg7PVPc5LqRTGtpoHE5WiNwGXd2jqITvAM=;
        b=fVogCfsCd+/bRwN/ajeM89TYPiyPlzDkwy2j1Mkk3bHoxWSdbDv4qHx2iEPbyv67oU
         jaIL4RHAQP0gtrPf/dfIS8lp9RNryAOqe5yfzjv9d+40cXclGjqT78NHxIbXNVofK5SV
         4rn+0AHDDwRMUkT7fZdedXBdPURGzxLlJJpLJE2pHiaUttAQ6lQNiAzNKs+omR9CCqdH
         qr6a7MO2lmz4AHF+0IwPYicDZuzsmXRGGlXfNTQqAkhL2kfFxXLCUpxLxdqgxcJ0ZpoS
         bV11xXU7QFZzwBpsBhh+BaRs8EJlj2jEV08FddAboxmUVderDj1IBT0Xk7+gZY+Lb4kK
         SHHQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Xh/fiPeIkvg7PVPc5LqRTGtpoHE5WiNwGXd2jqITvAM=;
        b=pWVmoauESAVQQnS9eUjMsaG3mMJ5/eSJd5wZCXO2tv3QopcQ560eV95WYiedFxC7Xd
         zLo3XW4UoeEnr29VGVFlDTPMKBxLpu59vPsy8RAn5dp2kKlBkxJbCjmxUFOnWLhms3sF
         aJIJkmeOcP0mP8VQPjSVdbt+AuEuom/61K4Raq+EHlpEclX2mxYwebfht81pdaacei+4
         IcrUxR17czyeaKAhG/Os+wRjE7Ypz9Yx+RisYjD7UlZFsa9cGlPd3SReIUVKasR97pTz
         5QSkmEYAEnioYA72JOTp0dS/BCAmQtcL5v5H7gMao/Rv7Bev9ce8nVX743i6VvIht/AH
         01MQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Xh/fiPeIkvg7PVPc5LqRTGtpoHE5WiNwGXd2jqITvAM=;
        b=ml+IDHAN339Ngaf3E+CWjaco73hsf43GoZRf1u5urR72lASIJVSfl/nonu3a3q6/r3
         Fh9f7Z6QzMtvqoQIHOmiwUvFcoC/wVHa8qEtKKhOXPqRoET+F27vJRjuHR+L7qm07UbU
         zAqT34yMBEKsS3gBGvFAZkOODkMIw56e/r4HLlmFStAArI7iMw0cCDBgEdz3pZzRw8E+
         eBT6LbEbeRHJAbYx3D6LHIRQNeqWFYOTHK6RyAwa8B1A1r/5txPBxJSjL9X19beep3ld
         Nw1tuMfX4kLISM/O6EhCyTlfnL7eP3JAaKfzW6nEFAIesHO9ABz6Sn5Wie+yaJlvc2dL
         l72g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53109bBZ79kggo9K4CPrJ0P9javLM5kevFXPr7HnIAC/JN0ZpBOm
	dIzM2qSpnq4cxhFvylfJGJc=
X-Google-Smtp-Source: ABdhPJxtS/mbJpIWCLd2aAiZxa1t0j9B8is8+fq2jIaHSgtqFZjWLR9b/sgo11hs7wsxWg87tq0Sgg==
X-Received: by 2002:a05:622a:c:: with SMTP id x12mr6344871qtw.502.1639492715359;
        Tue, 14 Dec 2021 06:38:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a81:: with SMTP id s1ls15256218qtc.11.gmail; Tue,
 14 Dec 2021 06:38:35 -0800 (PST)
X-Received: by 2002:ac8:57ca:: with SMTP id w10mr6505338qta.88.1639492714923;
        Tue, 14 Dec 2021 06:38:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639492714; cv=none;
        d=google.com; s=arc-20160816;
        b=NdIjYDTA9tq++D7t2bhf7qggDm5OA61fJ/3D52fcgSDfBIrw50I5WlgL6kDZH8dPCT
         1P/qf+vLrlbkdOYsf2Z8u0JlTuSH8opKOm4NEtsSGmoshkqrEX7CoE/Fk9wedIYLVkmO
         QBkk5mJU6bywdc1WQtKTikDk5DYZmXYJImXTcUy3HG+ljCkOZ2qvV4XNO/8v7lFEQI2/
         i11qFufbwvIIAgTaHuIwXLG5qI5rn9nLm2sUIZ4wlmwiHB37oNQzwTTAy8OMytN1bnGp
         CJWiKGNxjj9f3+6tF6NKWFoQWJrMeeOWCnj3gHApPfWPBF1d4bArsW9K6XmlXh4jk5ST
         s4Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=R4NvS2jKJuj6HSBgH45i5FwQuCehWvgVUBxINrvhBWY=;
        b=IYlJcloIN+wJfd1AroQ51IjeMTc3J4MJcyBfF2VvK3yECfJaF8SopNzITzUjM8859p
         h81yYmVP8UL0xa4wIbvJy3PYebz2L4YeBeDv9ZtAqqmzKzIxwVDZdbDxzK67BAHN5iTK
         Wxn06g9dvx55wWErJWlmrEGsEzoTmskNSaYvV/XRPYv9a856fxDr2uoons1avufTpeGq
         f1Ualq2QFPFq1lsLmT+GYEa/IZUBcTpoIRgscLU8jv4EpgRah1tn/ztAMSuCl2PFMc2G
         t7NANXxR28mQg2IGa1BH4VPxYPLZARtSOW33Fh8GsPRohsXuCeJmEA4p2L8MPuHDIAhJ
         WnZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=GOrcD4Bm;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id w9si4581qtc.5.2021.12.14.06.38.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Dec 2021 06:38:34 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id y14-20020a17090a2b4e00b001a5824f4918so17289563pjc.4
        for <kasan-dev@googlegroups.com>; Tue, 14 Dec 2021 06:38:34 -0800 (PST)
X-Received: by 2002:a17:902:e544:b0:144:e3fa:3c2e with SMTP id n4-20020a170902e54400b00144e3fa3c2emr6596816plf.17.1639492714139;
        Tue, 14 Dec 2021 06:38:34 -0800 (PST)
Received: from odroid ([114.29.23.242])
        by smtp.gmail.com with ESMTPSA id s16sm64466pfu.109.2021.12.14.06.38.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Dec 2021 06:38:33 -0800 (PST)
Date: Tue, 14 Dec 2021 14:38:22 +0000
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	cgroups@vger.kernel.org, Dave Hansen <dave.hansen@linux.intel.com>,
	David Woodhouse <dwmw2@infradead.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	iommu@lists.linux-foundation.org, Joerg Roedel <joro@8bytes.org>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Julia Lawall <julia.lawall@inria.fr>, kasan-dev@googlegroups.com,
	Lu Baolu <baolu.lu@linux.intel.com>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Marco Elver <elver@google.com>, Michal Hocko <mhocko@kernel.org>,
	Minchan Kim <minchan@kernel.org>, Nitin Gupta <ngupta@vflare.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vladimir Davydov <vdavydov.dev@gmail.com>,
	Will Deacon <will@kernel.org>, x86@kernel.org
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
Message-ID: <20211214143822.GA1063445@odroid>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=GOrcD4Bm;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::1033
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Dec 14, 2021 at 01:57:22PM +0100, Vlastimil Babka wrote:
> On 12/1/21 19:14, Vlastimil Babka wrote:
> > Folks from non-slab subsystems are Cc'd only to patches affecting them, and
> > this cover letter.
> > 
> > Series also available in git, based on 5.16-rc3:
> > https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2
> 
> Pushed a new branch slab-struct-slab-v3r3 with accumulated fixes and small tweaks
> and a new patch from Hyeonggon Yoo on top. To avoid too much spam, here's a range diff:
> 

Hello Vlastimil, Thank you for nice work.
I'm going to review and test new version soon in free time.

Btw, I gave you some review and test tags and seems to be missing in new
series. Did I do review/test process wrongly? It's first time to review
patches so please let me know if I did it wrongly.

--
Thank you.
Hyeonggon.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214143822.GA1063445%40odroid.
