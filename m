Return-Path: <kasan-dev+bncBDDL3KWR4EBRBANL6WSAMGQEAACTKBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7817374238F
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jun 2023 11:57:23 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-62de65b3a5bsf7444076d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jun 2023 02:57:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688032642; cv=pass;
        d=google.com; s=arc-20160816;
        b=QN4ExshT4XwFhrbZTk+P6m7TMCJzXYwPgnpbV2Z0DV9HJ4UWuxzxFWMi8Dh4Wh/VzT
         EcsNZ90yUBkjNyEmkC5KdcTzCeEsVBu+U6xCcWkgJgvw8fz6gWhp9SxPD23bdWxbuo27
         BjhYGLj6Euv3OpJi4NOBjcbdUUIUyOG+qDNrFU0W6mnnGH/5Scc6260YGGPiLzjd8Vst
         EHrfsXHNpxp+FbVmKm8z9CG9kc66d845viiIuk5Tl9HCQ8UIQx5OId2JxcbV4Uq4DhEk
         eOKbL2h/ebVeFDBrMTCPj/67LjXNXIXgBwN4nGJDWP0mqJZxumeeMPkFT4JV1tsgG3eh
         +ukQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=lLtUDJhTuQHPO7tBVVc/vZMLDHbhudWZwo0zwD6LhSI=;
        b=TXnardLtfHw2VDNPok8vdBT/+CKqjctlVEvWQzjFPcr+Ucr9egvGpEAgnAn6JlSFEI
         FTvG7BESjDztoZQWzrbeGgwN0GOKrelyM6wuV44bv8tr+B/k261xKsXtC8RLiyyTgEzG
         caSwXAXvZSg5vpileZxTeZMcwmj+R2v7VyEe0FD/qj82KqQWRVqtRpaXPtEO4cm0xp2i
         1fkxpG6PdIqYSGO7D2olvNkgoSebHeN0gv+mWMH5FLk71RxMsLsmgpQUx7wPeqUs4Z/o
         cmJVhsvz2ZRCShLEhtYT9deKG4R5B7uufSR42FUFqyGtbD6688xPqIyKAMP6viP5b1j2
         dyrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688032642; x=1690624642;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lLtUDJhTuQHPO7tBVVc/vZMLDHbhudWZwo0zwD6LhSI=;
        b=YSg7O7Se02gPHTUJGxmlFP3idbT9VZlihIrRtYyK6ProTDlb3Nf2PmFqh5aM30A6Me
         urX+Rw0xqCAEKbWRnRlfirnT0Q0KPS6DG3uwz9s8Wj1EW3HH1r+xm5dsO41KFHnbUmaW
         vAOk4gvQCUnsNHTvx7BCcRuPRteJCSou+WTUpRJr621BQplY/jOvNx2rzkT67l0rfjVC
         wyPcQh73PXydYyRY8xbow7iqcb9XUiPWQkl2M7m1wCWardJw3mw7pi5HbhAvUttaEOLS
         0l8F8yj2Ev4E2IFIVxN/09qpfiKT8lqpDzq6MlBKf7H2vJNRtQs/DR8T+fOHq/B6jqsB
         E+tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688032642; x=1690624642;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lLtUDJhTuQHPO7tBVVc/vZMLDHbhudWZwo0zwD6LhSI=;
        b=hO+7mHmbIPZAjCwCPw2CJHi2/gVAPZczfc3oQbAj3c+otsrJMNc3xeVrTVigDnnkGp
         nwq39uV9aXnioRaild6w4o5cjn2l/KoH7NeSy771xl3OANTiRCVuWRFh1xKs8XkmOJyo
         abNJyOwpng2tgtv5sy0z6arcuIvzwuD8klkqIO3r5nPz7CtoJS1VDOyEPyMLJIfNQjBT
         q9X/813t+kFvLGhWCu2WqEw1S0zLgkxJhgMFmLBKXtlpJnjicF+aqenTeTrqr2qD9dB1
         OxgQPnP2cvsXjZU8OTAvYDT2vkcboIHzdycHlZiESNLj4ln1Fcj/+MKofHIQyUq48g4P
         delg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDygY9LxFF5s7wY5mUV7l98bnTvyubB1X7mcvora+b/LVXT7KYRp
	LwqSXDkOBo7B9rmqvI8qUsY=
X-Google-Smtp-Source: ACHHUZ5P+NugNeFLGFzQlmDGCU/WEKJ8O8t/s+OztrwNoK7evYdi6n14MKY6scs1Ykcn7UwSSX2UIQ==
X-Received: by 2002:a05:6214:1cc1:b0:634:87c8:6a3f with SMTP id g1-20020a0562141cc100b0063487c86a3fmr18751865qvd.46.1688032641902;
        Thu, 29 Jun 2023 02:57:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:59c3:0:b0:632:629:1e98 with SMTP id el3-20020ad459c3000000b0063206291e98ls854538qvb.2.-pod-prod-09-us;
 Thu, 29 Jun 2023 02:57:21 -0700 (PDT)
X-Received: by 2002:a05:6214:5098:b0:626:379:6b0a with SMTP id kk24-20020a056214509800b0062603796b0amr35643484qvb.13.1688032641309;
        Thu, 29 Jun 2023 02:57:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688032641; cv=none;
        d=google.com; s=arc-20160816;
        b=I3fPhiS3Xt1HlMBsUAcDmtaz1ezgk6Q4OAKcyWm9iXIKRSN3UpPw4elm262NMQx86v
         OFL/JwZh1XpEk5sH3OQWAbZ7NOIOYU9uZnnGo9jTpHNvwsdY3QTewL4WeForlB1Y9b08
         fNJXM6oLOVLHH9g+ButTH47sEhymdTUDsM/NhzwBkGMbTRzt8kWoBfPOfoukTC9FWPMu
         Ag2VgkHD1+gGxgaOOL9GfodMOdTm8x7jIVsmk93b/Ttcw5V2gbBZWk5xVhieD6rUnM3i
         Mi5GBeSoqT7cxjVBq7YoMSfdcjdO7PnStS3ASpcV2JN47be2BDvyptRK79UmcT6WipLH
         sMBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=wgFURRDh/R52N2NpZ1Hil8mqsiYjBZRb47jqTE3MxjM=;
        fh=Qa1Y0ps5ftdzx0IPiPS0lN0Wc+3KnogNQ3kduK0iShA=;
        b=ieSo9ADzNLEUd4yze0bQhqsrckjSMe1lxjyMJKVKOGnSAqv9uXyPic4w6BPAgue4DQ
         2uyOy9rIGVRgY1AXMTRSsX8ynO+HcG7cu4E+vTPsFobDUtMW+2IgA0lOMXNuUHplgqMv
         Z6jdxksuFiCjEyHbrAqHMe7/CV/KAv5GkETWaENll4q2XCycB4z+gfVBQaL1wvyeXKD3
         TFUX6S/pMIFUfbvGHhONHwKz/shVJ2QP9nKmB+S0hOCewkrvbOI6j/ojwkfDungBbLlS
         mm49HBeuFitiUg8ns3b0ajpZ3jqHP0aPLqQvKvkJ1IUSy4+B7DbvTe8/tAlCBc4aJgyC
         yhmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id q18-20020a0cfa12000000b0063627a022b2si72497qvn.5.2023.06.29.02.57.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Jun 2023 02:57:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D214E61464;
	Thu, 29 Jun 2023 09:57:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 38882C433C8;
	Thu, 29 Jun 2023 09:57:17 +0000 (UTC)
Date: Thu, 29 Jun 2023 10:57:14 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Peter Collingbourne <pcc@google.com>
Cc: Will Deacon <will@kernel.org>, akpm@linux-foundation.org,
	Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	"surenb@google.com" <surenb@google.com>,
	"david@redhat.com" <david@redhat.com>,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Kuan-Ying Lee =?utf-8?B?KOadjuWGoOepjik=?= <Kuan-Ying.Lee@mediatek.com>,
	Casper Li =?utf-8?B?KOadjuS4reamrik=?= <casper.li@mediatek.com>,
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
	vincenzo.frascino@arm.com,
	Alexandru Elisei <alexandru.elisei@arm.com>, eugenis@google.com,
	Steven Price <steven.price@arm.com>, stable@vger.kernel.org
Subject: Re: [PATCH v4 1/3] mm: Call arch_swap_restore() from do_swap_page()
Message-ID: <ZJ1VersqnJcMXMyi@arm.com>
References: <20230523004312.1807357-1-pcc@google.com>
 <20230523004312.1807357-2-pcc@google.com>
 <20230605140554.GC21212@willie-the-truck>
 <CAMn1gO4k=rg96GVsPW6Aaz12c7hS0TYcgVR7y38x7pUsbfwg5A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAMn1gO4k=rg96GVsPW6Aaz12c7hS0TYcgVR7y38x7pUsbfwg5A@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Jun 05, 2023 at 10:41:12AM -0700, Peter Collingbourne wrote:
> On Mon, Jun 5, 2023 at 7:06=E2=80=AFAM Will Deacon <will@kernel.org> wrot=
e:
> > On Mon, May 22, 2023 at 05:43:08PM -0700, Peter Collingbourne wrote:
> > > Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") mo=
ved
> > > the call to swap_free() before the call to set_pte_at(), which meant =
that
> > > the MTE tags could end up being freed before set_pte_at() had a chanc=
e
> > > to restore them. Fix it by adding a call to the arch_swap_restore() h=
ook
> > > before the call to swap_free().
> > >
> > > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > > Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f84104=
9b8c61020c510678965
> > > Cc: <stable@vger.kernel.org> # 6.1
> > > Fixes: c145e0b47c77 ("mm: streamline COW logic in do_swap_page()")
> > > Reported-by: Qun-wei Lin (=E6=9E=97=E7=BE=A4=E5=B4=B4) <Qun-wei.Lin@m=
ediatek.com>
> > > Closes: https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d=
780d434.camel@mediatek.com/
> > > Acked-by: David Hildenbrand <david@redhat.com>
> > > Acked-by: "Huang, Ying" <ying.huang@intel.com>
> > > Reviewed-by: Steven Price <steven.price@arm.com>
> > > Acked-by: Catalin Marinas <catalin.marinas@arm.com>
> > > ---
> > > v2:
> > > - Call arch_swap_restore() directly instead of via arch_do_swap_page(=
)
> > >
> > >  mm/memory.c | 7 +++++++
> > >  1 file changed, 7 insertions(+)
> > >
> > > diff --git a/mm/memory.c b/mm/memory.c
> > > index f69fbc251198..fc25764016b3 100644
> > > --- a/mm/memory.c
> > > +++ b/mm/memory.c
> > > @@ -3932,6 +3932,13 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> > >               }
> > >       }
> > >
> > > +     /*
> > > +      * Some architectures may have to restore extra metadata to the=
 page
> > > +      * when reading from swap. This metadata may be indexed by swap=
 entry
> > > +      * so this must be called before swap_free().
> > > +      */
> > > +     arch_swap_restore(entry, folio);
> > > +
> > >       /*
> > >        * Remove the swap entry and conditionally try to free up the s=
wapcache.
> > >        * We're already holding a reference on the page but haven't ma=
pped it
> >
> > It looks like the intention is for this patch to land in 6.4, whereas t=
he
> > other two in the series could go in later, right? If so, I was expectin=
g
> > Andrew to pick this one up but he's not actually on CC. I've added him =
now,
> > but you may want to send this as a separate fix so it's obvious what ne=
eds
> > picking up for this cycle.
>=20
> I was expecting that this whole series could be picked up in mm. There
> was a previous attempt to apply v3 of this series to mm, but that
> failed because a dependent patch (commit c4c597f1b367 ("arm64: mte: Do
> not set PG_mte_tagged if tags were not initialized")) hadn't been
> merged into Linus's master branch yet. The series should be good to go
> in now that that patch has been merged.

Did this series fall through the cracks? I can't see it in linux-next
(or maybe my grep'ing failed). The commit mentioned above is in 6.4-rc3
AFAICT. Unfortunately Andrew was not cc'ed on the initial post, Will
added him later, so he likely missed it. For reference, the series is
here:

https://lore.kernel.org/r/20230523004312.1807357-1-pcc@google.com/

Andrew, what's your preference for this series? I'd like at least the
first patch to go into 6.5 as a fix. The second patch seems to be fairly
low risk and I'm happy for the third arm64 patch/cleanup to go in
6.5-rc1 (but it depends on the second patch). If you prefer, I can pick
them up and send a pull request to Linus next week before -rc1.
Otherwise you (or I) can queue the first patch and leave the other two
for 6.6.

Thanks.

--=20
Catalin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZJ1VersqnJcMXMyi%40arm.com.
