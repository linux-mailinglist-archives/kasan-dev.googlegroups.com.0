Return-Path: <kasan-dev+bncBC7OD3FKWUERBB7F7WXAMGQELE64TRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 1382086B666
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 18:51:05 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3651fbce799sf1785ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 09:51:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709142664; cv=pass;
        d=google.com; s=arc-20160816;
        b=R2Ru0d1U8/nOLA/cMyqWvVQfDRMbtCrU816Ymj4bBbCsqcwa3pL1R+L4CfExz92Kwg
         FBytWVNs7ErLFOIUjUGQQOKstFp7OQNvIWQAD9zM8J3T4Bd5ys/waDSMN61R+E/GxESZ
         suPBIF6q4epXT/g9hSWLWjk21tv0QF3xs/VwftqTakAwQBOq5JXFtQTlDyaBXzsyWVZz
         3YRME8QJqtnLL/4k3UQOqPkQFPBzpaIde+DvEoVP57WpyQvxmIRs7cUGlmlQ7l/v8znL
         qHAabz74RU4x061D8blalzI66bbgjZeSJBrnfAQ4+Oah5PUgzzI9q/8H+y2JcjJzSIrI
         +cnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Tp5vGPRuWkL90qzk2kYFvOjSMq0okErwwCwOuSA5p74=;
        fh=Ri9jiylbEalsx2T3Ff0DTmi/zoAhUmBeW5JFk6UXaQs=;
        b=s0WEIRXnTqVxmY6gPAam12+Blry5sPmYOWPAw05KyzPPS4graRub3w/7hqZnBpmFu7
         9+BdEHog8kwfwkL4f3PliFxUhe6AztNwlZh6lPlxt9UJlqHjWUQUY/gmIBJKhFyIV+gA
         cFy/GVVLp2I1JwWo9wrtwNf30sjxhF6f7iBTCHEorReo7+Yw/vB+ojFVf11q5vJzS/Qh
         tSOtv1xRPpx3wSZIOnmovyQBp9AjkMmsj+dh4COFC58LJYqhvKAx6JJ4GBN2j6df2Z6F
         ghIExTqoYLDfRTqJRC6BY3Fu7Tax+5qW1Jq2JagJSdHLHufDjPFMctV76Z8JbVpN5eKL
         rYsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=J4j1zjoj;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709142664; x=1709747464; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Tp5vGPRuWkL90qzk2kYFvOjSMq0okErwwCwOuSA5p74=;
        b=Id94f4mAoG8z/jJnOHd73ONjGEmvZa3iTcIaly6dUQI3tjUZ4rexLlmGahA1FTRpro
         P6UM5dZXuL7+z2wco8QU2srEZvfQBTEi4kROlifZx6cU8jUljz8eGPjJJlVyZRu/BYAo
         IvrGImoZSNzvS3RQ3QIeHRjJCS/RnuuGQj6UlPIx3LI7lH3Ykpwy2tu8niYLuX8vrZYn
         gXBuYU9JfYP+2IVCyAhPqlOtMcTFfjxwSN7hwayVsjAm1uzfwrkzRmE+aGenn60wDppg
         EDQwLRi0YPpPMU4Y1VJ2UkmAtSPmgKybIYKk1hVas7nnTPiaJh/1QxqGZVFdig5Uf4Z2
         oGUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709142664; x=1709747464;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Tp5vGPRuWkL90qzk2kYFvOjSMq0okErwwCwOuSA5p74=;
        b=vzRmOgzI7FkC+j1570hBRqDXFGuXTOy+ovfot3cK4l1hkm/SJ89YyfhnGc05CTe8KY
         avoHqv7Yq0y+GkexKqSr0WVdim0CrL4rt+vOKbr+RqpI3cXrV6DLhKmqe3oNpDSpCIzW
         2v3G7ajzHrMLQa/opTnWdVoX0mrPd7cn5X/aokh1q/CyJ+aSHPJhjqUuTdzM28mC0lEH
         5E2yszq8AU9cpTsFRpG4pBOjQ53JBNIc18j1WZojYeykkBtWuavXNHtDxudMI6k6B+c9
         OZbIz5nmPwQFTwg4DdH97rE/UI/t1rdtdjYun1n5CCysKSdHbLY2bRPhmttF+u3wLsJp
         iGKA==
X-Forwarded-Encrypted: i=2; AJvYcCURO7saePdpuFFb0gFM4NPZkp/zv7mY/4/wIoMjp7e7i0/ksIrH9O5ZpZa0oC+XYXTFeFr1h5l5J0AJZbelTZI+gqasqtT+Fg==
X-Gm-Message-State: AOJu0Yzs5StHLUM/ztXSw+p5x4RUYCR1VhT+9yPlIbxgyEQCS66Q/ezH
	v7DuQtk9e0tr4NsO+i4sKt+cPnY4abDL7aiaxQYCsfUMGcTOT9zw
X-Google-Smtp-Source: AGHT+IFdyv3d9oHGzUHK3tskvKsqJphKPzqXLxQxKHfBqSd4+u8Z0gGJc7Hfe4f62RSsUr4kO1QQOg==
X-Received: by 2002:a05:6e02:370e:b0:363:d154:ca92 with SMTP id ck14-20020a056e02370e00b00363d154ca92mr92243ilb.14.1709142663807;
        Wed, 28 Feb 2024 09:51:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:364c:b0:21e:5c6b:af5e with SMTP id
 v12-20020a056870364c00b0021e5c6baf5els81315oak.2.-pod-prod-03-us; Wed, 28 Feb
 2024 09:51:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXqO//Br82u1l4xR1l55wRzMiT1VVPReWkocYRfbB+AUG4y1LYOGnDBnyxfGj8jO5cbDYMlkEJSK/F5vtV37JEzHxDgxni7BRil+w==
X-Received: by 2002:a05:6870:420f:b0:21f:397c:bf52 with SMTP id u15-20020a056870420f00b0021f397cbf52mr443052oac.45.1709142663014;
        Wed, 28 Feb 2024 09:51:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709142663; cv=none;
        d=google.com; s=arc-20160816;
        b=z6N0+UO21s4pYvfAMpVjnuC+lNB/ciszhnjYVo1t5liBvhcCka6YN+RT7BUlxzXyHS
         aHS9/e+D7ApgJWAa/ubJXLTu5y/yjH7S28QhMfNCoZ/7qFVDxmvtlYFTDVeoX//mYCfE
         E7pV/4gXiH8Yk5AlXICcspolMpXnjONOc26Q9g1oOT2A0QY1OEMWN3t+ult1SutPPPEC
         sl7ncL2wkx1fuUFoJz7TXAvbTATaYYCXvgiMrTsRyz/cIxdsR1pHwW1b+7TXk5wHEM5O
         bQPBgXj2CgGQ3vM7L0b1pUhCSLNLlmswxLNpW4DdD4p84RsyGUJtsGt/6SAJED1cW6iK
         EcLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VnQ/ab/JPnAloJ9klQyh8nICmNuzmA4WCeR9lmsJM4M=;
        fh=8aZFkftuU7K/G5Cko9AaYG9OOIV//hP4WJJHf5+OKwk=;
        b=lsJDlWWr5tQGzq5Su/5HaJjTrjqjR/n/KR9asHVnUl1tKphlN0Lq1ZPoUbEpbysFao
         MwCvSV7SV3AG87+WkL/ztQhJZvXXhSs/Go2IjB48vU7BZXRpVgNh6Hcc2vglosze6mIU
         q+v4Q7qMBpQm14keHPk+FdIABp1iEXIlwEqOHkp8t+NFbF753pcGlcJKzZ4jbDvgBhHx
         f9stJ0IcQUYQYANg39eq4VjVyYPTTmEpEZagECFYGLama01AjQbfaQ4Y8ST0Lz8PXKvq
         sHbwpgmttP5gmU5nr+VPk08XVmWIEvDk/mFPhoD81AQChRu4ea44MEXj95ob4spTa95W
         DNXw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=J4j1zjoj;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id fw16-20020a056870081000b0021fd1e6d920si1156021oab.2.2024.02.28.09.51.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Feb 2024 09:51:03 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id 3f1490d57ef6-dcbcea9c261so46392276.3
        for <kasan-dev@googlegroups.com>; Wed, 28 Feb 2024 09:51:02 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWCNMXLP5RPyo0WYoOL4ys6LfeNUoAL/gc+fttlGcg/3ePEtraBSlOeg+/f6GvWrSHb8YhGQ6wD4rb/rf9IsOAwgww8KeGhwmV3Ew==
X-Received: by 2002:a25:9c08:0:b0:dcb:bff0:72b with SMTP id
 c8-20020a259c08000000b00dcbbff0072bmr3550ybo.31.1709142661963; Wed, 28 Feb
 2024 09:51:01 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-20-surenb@google.com>
 <2daf5f5a-401a-4ef7-8193-6dca4c064ea0@suse.cz> <CAJuCfpGt+zfFzfLSXEjeTo79gw2Be-UWBcJq=eL1qAnPf9PaiA@mail.gmail.com>
 <6db0f0c8-81cb-4d04-9560-ba73d63db4b8@suse.cz>
In-Reply-To: <6db0f0c8-81cb-4d04-9560-ba73d63db4b8@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Feb 2024 17:50:50 +0000
Message-ID: <CAJuCfpEgh1OiYNE_uKG-BqW2x97sOL9+AaTX4Jct3=WHzAv+kg@mail.gmail.com>
Subject: Re: [PATCH v4 19/36] mm: create new codetag references during page splitting
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=J4j1zjoj;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Wed, Feb 28, 2024 at 12:47=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> w=
rote:
>
> On 2/27/24 17:38, Suren Baghdasaryan wrote:
> > On Tue, Feb 27, 2024 at 2:10=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz=
> wrote:
> >>
> >> On 2/21/24 20:40, Suren Baghdasaryan wrote:
> >> > When a high-order page is split into smaller ones, each newly split
> >> > page should get its codetag. The original codetag is reused for thes=
e
> >> > pages but it's recorded as 0-byte allocation because original codeta=
g
> >> > already accounts for the original high-order allocated page.
> >>
> >> This was v3 but then you refactored (for the better) so the commit log
> >> could reflect it?
> >
> > Yes, technically mechnism didn't change but I should word it better.
> > Smth like this:
> >
> > When a high-order page is split into smaller ones, each newly split
> > page should get its codetag. After the split each split page will be
> > referencing the original codetag. The codetag's "bytes" counter
> > remains the same because the amount of allocated memory has not
> > changed, however the "calls" counter gets increased to keep the
> > counter correct when these individual pages get freed.
>
> Great, thanks.
> The concern with __free_pages() is not really related to splitting, so fo=
r
> this patch:
>
> Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
>
> >
> >>
> >> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> >>
> >> I was going to R-b, but now I recalled the trickiness of
> >> __free_pages() for non-compound pages if it loses the race to a
> >> speculative reference. Will the codetag handling work fine there?
> >
> > I think so. Each non-compoud page has its individual reference to its
> > codetag and will decrement it whenever the page is freed. IIUC the
> > logic in  __free_pages(), when it loses race to a speculative
> > reference it will free all pages except for the first one and the
>
> The "tail" pages of this non-compound high-order page will AFAICS not hav=
e
> code tags assigned, so alloc_tag_sub() will be a no-op (or a warning with
> _DEBUG).

Yes, that is correct.

>
> > first one will be freed when the last put_page() happens. If prior to
> > this all these pages were split from one page then all of them will
> > have their own reference which points to the same codetag.
>
> Yeah I'm assuming there's no split before the freeing. This patch about
> splitting just reminded me of that tricky freeing scenario.

Ah, I see. I thought you were talking about a page that was previously spli=
t.

>
> So IIUC the "else if (!head)" path of __free_pages() will do nothing abou=
t
> the "tail" pages wrt code tags as there are no code tags.
> Then whoever took the speculative "head" page reference will put_page() a=
nd
> free it, which will end up in alloc_tag_sub(). This will decrement calls
> properly, but bytes will become imbalanced, because that put_page() will
> pass order-0 worth of bytes - the original order is lost.

Yeah, that's true. put_page() will end up calling
free_unref_page(&folio->page, 0) even if the original order was more
than 0.

>
> Now this might be rare enough that it's not worth fixing if that would be
> too complicated, just FYI.

Yeah. We can fix this by subtracting the "bytes" counter of the "head"
page for all free_the_page(page + (1 << order), order) calls we do
inside __free_pages(). But we can't simply use pgalloc_tag_sub()
because the "calls" counter will get over-decremented (we allocated
all of these pages with one call). I'll need to introduce a new
pgalloc_tag_sub_bytes() API and use it here. I feel it's too targeted
of a solution but OTOH this is a special situation, so maybe it's
acceptable. WDYT?

>
>
> > Every time
> > one of these pages are freed that codetag's "bytes" and "calls"
> > counters will be decremented. I think accounting will work correctly
> > irrespective of where these pages are freed, in __free_pages() or by
> > put_page().
> >
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEgh1OiYNE_uKG-BqW2x97sOL9%2BAaTX4Jct3%3DWHzAv%2Bkg%40mail.=
gmail.com.
