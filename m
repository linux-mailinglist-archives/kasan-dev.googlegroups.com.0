Return-Path: <kasan-dev+bncBDKMZTOATIBRB7GI667AMGQEEOUU52A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 070C7A6C5A9
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 23:13:19 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-30d8a6be01fsf883521fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Mar 2025 15:13:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742595198; cv=pass;
        d=google.com; s=arc-20240605;
        b=DOFQ09Hztk5jTJB19WR+92HEo0BHc5dRmyIFLYjU7iayN15r2QwjOBL+UBIiJejPTE
         2aA5niUzzyKCOvcXqdhRJUi1/Cfvi8SQeagAol4sZTAGjEFIVGWWzfBArXTsk31QhQQr
         ogAAWYTu5gX6/scjBNjO5W9WgyqWm+RnVl+1kmf5B+L0KB4mkRPAYwQvgjfjqqkWRwKY
         Y2UctLU7aBubuFiu/xJh3SvTA5jv5cja4RbCrGX+P35TxFVXfWxlmkHnvMI3XUIx3Tcq
         tyYyDQrE+ZNIkkdNb5WiViG1HA+7P8fkpOhaGR6vtaNTiji2PfkQpBwtaHs7F8aZbdVC
         ZsQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=14lEy4SNHIF/+wbpWge4Km0sEYgnIk81DspdOIPtJtA=;
        fh=em6TGHMrHOeGLipx7FfrNEYjfa2P3/x9O5SEJhdlHZc=;
        b=cBzkg+AEsoWVMgotaSIwZhhKt/OVjlkcH5Rfq4bE8+HACCujmp9ZVXCkBE5Uz5oiNG
         8W+65n6WdT3vKO49ETXNAeGWEUIWHC0TVBMBzA3V4uNyzWWQEbyt75nI85L2qli7l921
         cW2XgpMpL77252WZlDr21Nq/oXbuhzFujuRByAffBDDOTH7q4o/z0uhj5ViaLrBjFQ16
         UEKnzol1bm5BhJ3EZ47MOykEcJWkMENxS3littVANfXIrG3Q7pCeXmEZFtWMO5ihfYxx
         KlW4gVprSKpQZHTh60KHIDKfuK7dwHKEoi+zn9+g3eGV6PN3f5jSb7ADzVCW8PisOkdI
         VqEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=il7rfHak;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::ad as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742595198; x=1743199998; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=14lEy4SNHIF/+wbpWge4Km0sEYgnIk81DspdOIPtJtA=;
        b=YhBeXdSgqzEqSVeUy8cjTjnV4vC9lknVCCjEpT38GN+Nm5jK3MtrOp0QPV1Gf5UrN6
         vGrUVnTEqrtGpKVmXIi3Uq3vDxFmdXz/pK9c6ug+C0DwI4gexDrhMlz06TNhzYdyRFUn
         dDjm6yys9xFx+RAe3o3XJxHwVGTvhs/405ROET+NjRY+iDGopy0MJnsPIa3nHouHI8ml
         rUQVQUEj2/uv65P+FhW0lQqM7xuRhvOeHyk5N/K1aHZ6w1hi+7yjA36FRW2W8OAgoU/i
         Hc0n/kqlD1UhO8cEqQoROA70br/ZfWJ4yEW8FwWGFHtGu5NCjOvqubpTwkHSfWkVFoYi
         nvgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742595198; x=1743199998;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=14lEy4SNHIF/+wbpWge4Km0sEYgnIk81DspdOIPtJtA=;
        b=rdzfFJ06PByqkSkvRy4+Sp5exuiBE9AgqC+du6G0YzWbFUQ3R5BmHal8czhhifrJoN
         PydGOE2SuL/gZEAOS8PNougvLPmPrBioWxh8xftvWpDARZBKzda98ns8iNR95VuUtkeY
         kVEy682yUpR5By9TW7IYD8Vf+Xb9hlP1/2v4OEjrEJuv2cCAED8bNcvoyVLLfdpgmmyV
         T6Y6UcpFdpagi7YKJBz8kYzgmP3jFo7yPMb2kyJ825rSsVGzqyFFeq8XPMWcFxD+YwkU
         fK+1r957WLX2ddivH9U7rgPMv5NYyXQpm31bwBTeQP8Pf2zRo43lecTIpU1n9LOC0uLL
         aDjg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXhTt1hsgLY0ZUA+TMPbXWVqLWeZkJAMplYvK/TVOK8QseUne7nPMuWnKvvu1Pim6BwkSVZLg==@lfdr.de
X-Gm-Message-State: AOJu0YzfBdJqc+xNwCeNMzcNFptV2iLZOzKiYQgT3hnxCLFSkr4Z3trp
	700FscV9zzfnuJTf4raQ3Lp3hlwPNy8hrDPCZ9vB0pKV15pa8Cg6
X-Google-Smtp-Source: AGHT+IGfwphprHeuSBFElfUCWxeZb4s/Hi7XZUw7EYccedqVFP32wSUe5UXnObaNexrtq2+AGXMpLg==
X-Received: by 2002:a05:651c:154a:b0:30c:5c6:91cd with SMTP id 38308e7fff4ca-30d7e222a4emr16387381fa.13.1742595197403;
        Fri, 21 Mar 2025 15:13:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJmHLxEMOM5UZjD9MTzMr8B1VH7pOWD/octKvnUBNOgeQ==
Received: by 2002:a2e:8846:0:b0:30b:c79f:c79 with SMTP id 38308e7fff4ca-30d7283bf6cls4746951fa.1.-pod-prod-01-eu;
 Fri, 21 Mar 2025 15:13:14 -0700 (PDT)
X-Received: by 2002:a05:651c:541:b0:30b:b78e:c449 with SMTP id 38308e7fff4ca-30d7e22262fmr19013421fa.11.1742595194201;
        Fri, 21 Mar 2025 15:13:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742595194; cv=none;
        d=google.com; s=arc-20240605;
        b=UoTj2uXCRKh4uD37rMXFKPjUOBIt9e5AahpX7CQAoMjdfaA97irtZSVGigJCPhMkaY
         fDxWeSr3qhLbxWXWFrTrvn+yowayuUzPHUQdAajD4Lm1QSmDOgTi7oKceI2/fZliJJ7X
         UNdSghDVyC/eshvQ/F/nrA+AUUUggUFikMhY2cCVhBBtwLxfqyTtgJB22Mx42uBrlsQq
         v0VJJenf18zmGNb2tkfL51HdTlNgkSmvijzPqUxyiCa0Wi+898nd5iV8vZnmuHV9epgQ
         wStSGyXvKxmn/UVDMvTjohQD3JeBC6LuK4PlAN2PljtJF73C1HBzSjsvDoYisWjzrz1Z
         c2cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=qLmsI/qoF2lA3iHT6tFb4P7tsovh+Nw7+TxRu6LeWjA=;
        fh=7vXUBfeIBhZajighND0JabQYQZtyfxRFM7iIgOFeMTQ=;
        b=lswQ2cDtJgxX8sS5bbglJoRDbpjfedxe9ah+PFtlqTm+rroorL7YDYVURZog5BEWk6
         43YieXrPr6IYpj4VhHG1v+YIh4vbpQMHaSC0Kzs8s7rqmvBePJqNro4LioQTastPO7CX
         /9Ef/QxK8lndIPKGh61VAoxFuZ9uzq5xZIYQ0hN902rQA8nGXvsy9WEZLqNYSuMDD87y
         uiW8MlpgpccM/Kc6W4j6iLcYJ82758ON3D10+ecU86OJ3wr0e8R/s2rfLMtnM//m+fY7
         /rr1YfuvLvfQRwBH69tnA79g4VfN0auYlCizQquJeRG2vh2vKlcTmYjGOv6GZz0zVYwg
         EazQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=il7rfHak;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::ad as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-173.mta1.migadu.com (out-173.mta1.migadu.com. [2001:41d0:203:375::ad])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30d7d8575a4si598841fa.6.2025.03.21.15.13.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Mar 2025 15:13:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::ad as permitted sender) client-ip=2001:41d0:203:375::ad;
Date: Fri, 21 Mar 2025 18:13:06 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com
Subject: Re: KMSAN splats with struct padding
Message-ID: <mt7vtapgmfzppkgfgkqmpu57abpfmnm7zlqzjjbklb7phbpo5a@h7g3sxtf3gvy>
References: <5vpovh73ejzfodl2gpdx7hqr6d5tssivk3q3ibqx7do7gqwwam@pgx44qj76bzr>
 <CACT4Y+YR2XBhGmjAhOEb=YdE4k1cSHzNKtqSdDcCP6znbh4myA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+YR2XBhGmjAhOEb=YdE4k1cSHzNKtqSdDcCP6znbh4myA@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=il7rfHak;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::ad as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Fri, Mar 21, 2025 at 02:32:29PM -0700, Dmitry Vyukov wrote:
> On Fri, 21 Mar 2025 at 08:47, Kent Overstreet <kent.overstreet@linux.dev> wrote:
> >
> > I've seen a couple cases of kmsan warnings due to struct padding - or in
> > this case, no actual padding in the top level but a lot of fun union
> > games - which are probably treated as padding by the compiler.
> >
> > I was under the impression that compilers not initializing padding was
> > getting fixed - is that not the case?
> >
> > If not, perhaps we could still get some help from the compiler in the
> > form of a type attribute?
> >
> > BUG: KMSAN: uninit-value in bch2_disk_accounting_mod+0xcc0/0x1c30
> >  bch2_disk_accounting_mod+0xcc0/0x1c30
> >  __trigger_extent+0x5a5b/0x5d20
> >  bch2_trigger_extent+0x7f4/0xf30
> >  __bch2_trans_commit+0xac9/0xc2a0
> >  bch2_extent_update+0x450/0x9e0
> >  __bch2_write_index+0xf53/0x2810
> >  bch2_write_point_do_index_updates+0x55e/0x940
> >  process_scheduled_works+0x7d9/0x1580
> >  worker_thread+0xc17/0x1170
> >  kthread+0x9c6/0xc70
> >  ret_from_fork+0x5c/0x80
> >  ret_from_fork_asm+0x11/0x20
> >
> > Uninit was stored to memory at:
> >  bch2_disk_accounting_mod+0x17ad/0x1c30
> >  __trigger_extent+0x5a5b/0x5d20
> >  bch2_trigger_extent+0x7f4/0xf30
> >  __bch2_trans_commit+0xac9/0xc2a0
> >  bch2_extent_update+0x450/0x9e0
> >  __bch2_write_index+0xf53/0x2810
> >  bch2_write_point_do_index_updates+0x55e/0x940
> >  process_scheduled_works+0x7d9/0x1580
> >  worker_thread+0xc17/0x1170
> >  kthread+0x9c6/0xc70
> >  ret_from_fork+0x5c/0x80
> >  ret_from_fork_asm+0x11/0x20
> >
> > Local variable acc_inum_key created at:
> >  __trigger_extent+0x58e7/0x5d20
> >  bch2_trigger_extent+0x7f4/0xf30
> >
> > Bytes 20-23 of 64 are uninitialized
> > Memory access of size 64 starts at ffff8881d998efc0
> >
> > for the code:
> >
> > bool insert = !(flags & BTREE_TRIGGER_overwrite);
> > struct disk_accounting_pos acc_inum_key = {
> >         .type           = BCH_DISK_ACCOUNTING_inum,
> >         .inum.inum      = k.k->p.inode,
> > };
> > s64 v[3] = {
> >         insert ? 1 : -1,
> >         insert ? k.k->size : -((s64) k.k->size),
> >         *replicas_sectors,
> > };
> > ret = bch2_disk_accounting_mod(trans, &acc_inum_key, v, ARRAY_SIZE(v), gc);
> > if (ret)
> >         return ret;
> 
> Hi Kent,
> 
> Do you mean -fzero-init-padding-bits=all
> https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=dce4aab8441d285b9a78b33753e0bf583c1320ee
> or something else?
> 
> The commit says "enable -fzero-init-padding-bits=all when available
> (GCC 15+)". Can/should kernel code rely on this being a guarantee? Or
> is it rather just a security mitigation for some compilers for cases
> where the code is buggy?

Seems not :)

That's a bit less than I'd hoped for, but thanks for confirmation...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/mt7vtapgmfzppkgfgkqmpu57abpfmnm7zlqzjjbklb7phbpo5a%40h7g3sxtf3gvy.
