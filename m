Return-Path: <kasan-dev+bncBC7OBJGL2MHBBENDW3CQMGQELOLUVBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F6FCB35A6A
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 12:50:59 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-70dd6d25947sf6901546d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 03:50:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756205458; cv=pass;
        d=google.com; s=arc-20240605;
        b=GjrYRC3AJSFmoRG2e9v6gFzLPR+r1f33t6eCpRsq6zMQLiDxr8ctN+2TnMKQovQOn9
         nnt8/AtNYAyHTEeGS3cehiNlw9x/P8NDzwizF2GsJR6W/Rn9BPN8z+szgvdrE1AcingQ
         qdNFgKwCqCQ5TK0LM3yYVFlwHZqGX/tfbMpK+HE6oQ9yQdp7EnKF08OqxUKwbgGrs6p3
         g1CBIb9KEYQroFAjjHEU4z0G3QdYNGygpRczjEAVhjwleyUjkrd+VTIyJFMRtMrq+pqQ
         a98ndJiUO57hlyaiPZTF+gQ2UHRml6NhE5mBtcZ5qJjtTQjAwttb/8iLAferfZrYMcFD
         PO7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=foeBeYQmGvAidnGlgUrNjWzgMdTUX26xPTNSytdKfDE=;
        fh=QgPDn+wHkLXiNozU+upCqDayryx0hb+Vx5xPydIOXFQ=;
        b=ZbxUmVJrUTlhMT7uHZiHecTKpWk/At0raBFyZN04V1moAf3YQ+dtcPRZRZIkS4+Arp
         +96KAKoUVafU1qoSxUqsc7YIf3E4ctIDhhUhhuJJlcEwjA5AyMqfhLE/eQNFYMeo27Ky
         KpRa8OxTdAzd7omY4T6hyDwPBpUCgMx7q1kEdfXXlhV4J4JImP1WE6IfzPVjiaNijvhu
         4/H0Orpk/zS+immi2oRA97aySNGVSpI8G5CrupJIlNTg3m7PsuDPzyWdUGuMM9u2WT1v
         vUlg8w5II7pQ0PLwgNJLmfSZWGINqL7aps6hhbTbCxsv87507fpxozIrQh+xmbn47oMr
         KGhQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OoAxIXYr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756205458; x=1756810258; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=foeBeYQmGvAidnGlgUrNjWzgMdTUX26xPTNSytdKfDE=;
        b=k4xjnKQbOxE8EZos4gdWHGVyO3y+jcC2vLiihsZdKvjx4tehXFaNpTN4+XH/N1nweH
         Be+8afs7wkal+Pnp9m+gPSEN4AhBJWhUV86RaLtW07I1AjWfXei4UgeAi2PQKI37+eXy
         0SzBLDSmFBmDKpT6340S3Vf4BcvYpbpBua04FzHgGgPyjLVPxbLZZvwzZJnDi/tAFUL6
         dAM//gHecTabMsW+3bAWNZIKPgvJnN/v+bOScz48Ll4BLhLpEOz5mFueOqCZVwEc4GcV
         bewPJc99IyI+GJv9XalLczfkXuH9P0FN5EL1JA62FhW/m74ktkAFdlHeUxvDK1tWz22t
         cdVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756205458; x=1756810258;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=foeBeYQmGvAidnGlgUrNjWzgMdTUX26xPTNSytdKfDE=;
        b=dz1n2Esa1IRPfl4G+cwYkPNIU96UvtSoU5ZzEy9qK/ZpBJyLUIPOHTm2l+mDFenHM/
         uE195p7tZVHdf8aO6KXFhI62QFRArawZPdb/cHaSorYxpuk3DWX8rS5PmAu217Wb7547
         UWIpS39KD4HetKMbs9v/yppOvs1l6y3U50rMDdTGvuGYsWsXwvZLNv2LAMc3iSItryte
         E3pMSx+h9K3cqIEGuUJyKgYxibiUCLrRpLrLWAp6wsMd3MmUe6vlh0T9WE5LVPZKrAQz
         fUsM5VJ9v/IfUYlu/hvbNk0rjj9a/EeAMWQCOpM3VyG5dkIYgNhAOqGJbO8yev+4OraX
         5uhQ==
X-Forwarded-Encrypted: i=2; AJvYcCXCUAC026ZnXRK2jRcehiDe19fChvJn82JC3uF2RJzg+Awa/16oQKjHqeSidY8urBTwgSOEHw==@lfdr.de
X-Gm-Message-State: AOJu0Yz2ikDLF+PzqOH5X24I6M1LHSXIyg0WS0td+Xqm0KS0bKU/YQdf
	zsEz+CLNnmGL8HMCNpUtwtJCaaXJa9LbNWtP9s18OycMsBOGMoEknQMn
X-Google-Smtp-Source: AGHT+IEI5b8eZdx9hYdzVt8LWcLfvkDkyPMZ00Q1RliseP6VJnPsOZNYET5LjG+gDFLktlY68SDoIQ==
X-Received: by 2002:a05:6214:3293:b0:70d:9f91:642a with SMTP id 6a1803df08f44-70d9f916d1bmr127360026d6.56.1756205457854;
        Tue, 26 Aug 2025 03:50:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd5wr4u5TvY4AuJILi8mUjkMhFB+eg3YU/zR090DJNwuQ==
Received: by 2002:ad4:5ce4:0:b0:70d:9fb7:7561 with SMTP id 6a1803df08f44-70d9fb77a6els60166846d6.2.-pod-prod-05-us;
 Tue, 26 Aug 2025 03:50:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXW2c7J8GBi00pNBilnlQcMVAGdA6YRmNzUejK8xrbzVJZvsDxhbsA4PdcwS6Xc4xKQMLgx1oN5X4Q=@googlegroups.com
X-Received: by 2002:a05:6122:179b:b0:530:6c3e:4db1 with SMTP id 71dfb90a1353d-53c8a2dab07mr3980781e0c.6.1756205456900;
        Tue, 26 Aug 2025 03:50:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756205456; cv=none;
        d=google.com; s=arc-20240605;
        b=gcXSJHGxGOIiZUGjab4SovORrjZgxpeKHrQUvlEUJN4bV3otGmukZ65ip3xLNEfOeg
         +HWwPMGL7840jjUaJ8XlLF+HD3YyVMIoSAd9nZtECGFwt9YtIVd2idnlZlGBY1eY5aLi
         pxSppMJ6AnjGC72a+C8xQofG5GtfqgMJJ4reGLi7i+0oMTsbCCGKHGBXVIg+z5wcakcB
         wzT5UDpieYjzbeR7KpFBZq/dxJRkau6OiEsXbXUbw2grIWEKQzCKko4yxD+676sm8kA7
         SQ8lzCx8AB6qUz9WZd0APn8p0GB9BhIBCEn8nldSKa+xXxzDScaOOVodHDJCknDs1Vs+
         kMRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LBKQHJXt7k5q/EQimxKbRfxnkhOmIaY3I8CzQ5DxlNs=;
        fh=og/A6xPZQfCaD1wiZ781BvBYUR47Ga1C7q7Gm//9qus=;
        b=K/eiPWD1qJylRzoSg8XD7VCGIQYAEYWNjin+RiJCS2dSVP+mmWYWLK+72dWvnxXh7u
         2Tu+EzyqpBHoFkgoa9+8drjB2CEcj9e61SVHQfU2znnKHrhhvPvUZo/tbA5zd/XEmfOU
         AprQeSvB6dCMimR5+YEFmuGrWhALrnJQCrBUfSByBRM98sTft5ERJ3RMplLYA4cK+/5o
         lLt2URdSSmq8anqq/TbBN8QzAusddys93y4LuPLUIOSZ+Hxkk+ATKqY90Kfx5kpiGJ2p
         ow0ef1jkaSINkefS1hvOnGeCORCYNAakK9VAjxzAiKHSIWzssq7I91ZDBDZeRRKpj7q6
         Nsdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OoAxIXYr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-53ed588c3casi442886e0c.0.2025.08.26.03.50.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 03:50:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-2449978aceaso38935965ad.2
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 03:50:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWa/52G/htgT+PCP/KvDoUrT13p1YtYK8D5WOH0MoAd9gSYqe/dybxffNIL8ETPsp67WEgOD/thP2w=@googlegroups.com
X-Gm-Gg: ASbGnctI2AIVcmEHq1l8lrpmrTAfyuvOS5huywkiP5/pBfMjhrqQsR+ScNO639OTjrt
	dR1nbYay1gf4Kpe3hknFNl7CwhHi8XYQq+lza6a1e8O9GWRNQTfENJICtYhbVmhTiheexXxWjiX
	lB12QNSjWQ17ibuJlmFsMUIHv9azA+yrmgHmx/zFLItkRa0XaqJNABsF/gVtTEm8gLLpzrD5hPX
	1LsZ3BAHoUci4p/ytKyoDE3I1o=
X-Received: by 2002:a17:903:40d1:b0:246:d00b:4ae3 with SMTP id
 d9443c01a7336-246d00b549dmr76053385ad.61.1756205455660; Tue, 26 Aug 2025
 03:50:55 -0700 (PDT)
MIME-Version: 1.0
References: <20250825154505.1558444-1-elver@google.com> <0DC67CE5-6006-4949-A81D-882DBDF4DAC4@kernel.org>
In-Reply-To: <0DC67CE5-6006-4949-A81D-882DBDF4DAC4@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 26 Aug 2025 12:50:18 +0200
X-Gm-Features: Ac12FXy7R8YoW-2EpRHczPhHZJ0RjV4YJMdaLPQVeIhDdwxbJBGrafjAEUd74Ec
Message-ID: <CANpmjNMpnyQ=PhZ4jkSiAR7gg8WJOiunoxwhRWuUD1U_EEnyrw@mail.gmail.com>
Subject: Re: [PATCH RFC] slab: support for compiler-assisted type-based slab
 cache partitioning
To: Kees Cook <kees@kernel.org>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	"Gustavo A. R. Silva" <gustavoars@kernel.org>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, David Hildenbrand <david@redhat.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Florent Revest <revest@google.com>, GONG Ruiqi <gongruiqi@huaweicloud.com>, 
	Harry Yoo <harry.yoo@oracle.com>, Jann Horn <jannh@google.com>, 
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, Matteo Rizzo <matteorizzo@google.com>, 
	Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Suren Baghdasaryan <surenb@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, linux-hardening@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=OoAxIXYr;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::630 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 25 Aug 2025 at 22:18, Kees Cook <kees@kernel.org> wrote:
> On August 25, 2025 11:44:40 AM EDT, Marco Elver <elver@google.com> wrote:
> >Additionally, when I compile my kernel with -Rpass=alloc-token, which
> >provides diagnostics where (after dead-code elimination) type inference
> >failed, I see 966 allocation sites where the compiler failed to identify
> >a type. Some initial review confirms these are mostly variable sized
> >buffers, but also include structs with trailing flexible length arrays
> >(the latter could be recognized by the compiler by teaching it to look
> >more deeply into complex expressions such as those generated by
> >struct_size).
>
> Can the type be extracted from an AST analysis of the lhs?
>
> struct foo *p = kmalloc(bytes, gfp);
>
> Doesn't tell us much from "bytes", but typeof(*p) does...

Certainly possible. It currently looks for explicit casts if it can't
figure out from malloc args, but is not yet able to deal with implicit
casts like that. But it's fixable - on the TODO list, and should
improve coverage even more.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMpnyQ%3DPhZ4jkSiAR7gg8WJOiunoxwhRWuUD1U_EEnyrw%40mail.gmail.com.
