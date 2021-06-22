Return-Path: <kasan-dev+bncBC72VC6I3MMBBE4KZGDAMGQEDG55CVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 03F973B0E71
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 22:16:21 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id r5-20020a635d050000b0290220f78694c8sf14485941pgb.0
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 13:16:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624392979; cv=pass;
        d=google.com; s=arc-20160816;
        b=tPt3KoX8aWGnf9f8cIT0Fc0hI3rk/hcKxtrJKM0tEeheoYLDGiv713xFNG6YykvGxU
         5FACgWocQjjWouq4HtV3QFzt1xsDXHapnTSLmniJ7+ynlif1i/e0UcRGng7/xyNmSfj/
         iv0mmyk3To62K3oLkQ1v9O4FHWCaMUu1SRKSAipaASNOwP96J98mRIUgadeLa8zT8xtz
         LtK2PIIe4ol7F8XHp+vcnNDxhXflNeIv+Gg1oaOAjZ5pANfkM+5+y8y9ehGV1gV3Xlee
         Kw0qmwi+zbaZogFisVstv9SoZkHVx7I31RzM9YVjFAOJQWMjhhzqR2bW2QewArLRgAwo
         r9xA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=VvoPmF0UeWfMXoDI7y52pPhExwuAdek2suhiXjal5vQ=;
        b=NDp/4FC8klnYMeBenojlCzPYPlriRqDB+c1zTjpnAFbbXuyqXl9b9xrcfZxE5dpkE9
         N5dY3+pASXatDG0JewFb8c/j4+gD6fRCOJMeuDdxtu4Cl1lV6bkH3JnF0SmueoA9pK5U
         /PJnWjh38CObjx5n9X7hYD6sbUzVCAFgtczrrprKVIrZ51FTabEO2WxnnqnRbeySy+3z
         +JpQHzi/JbyF6wBUVL+HYChFiSJxihMOplM+UiwOdVf25Sd+LI4w1Shmk2uSVW9V0VeS
         0iTuhfgpKQgzrZ2vIhiwLzRX3wpMoAnIPgLK/050UcHkj5SiuZCiYdLbQFJBtMB+v17e
         MYVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=brsp2b6G;
       spf=pass (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e2b as permitted sender) smtp.mailfrom=jim.cromie@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VvoPmF0UeWfMXoDI7y52pPhExwuAdek2suhiXjal5vQ=;
        b=jnJoXRFpCLRUf/F0+3g6L95PPWqTk4C1qhsN8TrbrGJvKr2w1hhrFuZg+Tkh3JM0br
         bDRonzCuabWu6T+UpVtu6ifigQxVN/ezoLFoCb+qlynLf+LhdiqH9rUIY3SkhuGnydZ7
         LPSMyBda6DrjSOkbsNL2MRDe8WRaoHanXfne1uGHF4a2BUwTRwZdBfeDJVBFHS28edFx
         LgZZLDi9fTwLI+GcXF4mm+auSdkt8OWEBHssGvoQXud2EvvZj8hWA4+FZ4AOL8ok9tuo
         8xgwbf5YGwVmbjd+LeMP6enAWeI9lPpFTbosQGpAY3/phr8bmCCEPjEkBdVjwns65JXl
         oK1A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VvoPmF0UeWfMXoDI7y52pPhExwuAdek2suhiXjal5vQ=;
        b=L2EIFVBd27cbVvXhWRzpU9C5s/1EqXYIkBV/bYuieufvzr/n87bN7BsyWWig2JSKKM
         BR6BzM4dgrmSQ7KsW51ZBoHe674/v4rbZ9d3ihozRGC5/bEOo/86keehTSY2XGWoRzNE
         xwqJ9wkRPISnhemV4y9KqKhLKnniRXYbJR0SeCGxfwrtha4XVBwvUV4esvt3XM0YsH3r
         XWZXQok3AGlS40lV6w3Yh/4t6GHQT6zF2qkp/69Gu67EViu9WLSgQqmyTt1N05DMoihM
         fD1wfnnJabIBY8wS0j2NESYBSuig62jZZ9mLELMfH/ZamI1qoSKa2Nv34/jvdduhhQu9
         y5LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VvoPmF0UeWfMXoDI7y52pPhExwuAdek2suhiXjal5vQ=;
        b=b3Gbjyivqs+ftVDUN4rsDIjGYLhdo3gSvc8BKTfTNG6pQ3ueV/QREP/jucELhX0QcZ
         SDWy+u5lzn+Gsng/s7e/mkf2/I3iSduzZPaQfihpZhpID2Sh+qJy1ofyg/MShHl5UhtY
         przb7e3dBmrN0EVhRtCz4yd6RrzW5ELCV0XQAn6Ikd5SkTAXcU8YTUurW0h6TONx+Ymb
         fikGkHWbTPpynx4v5X7X64OXxYtcSM57CzcrYBhZBc6h3SjxUgrzBC8u/ys2aGqWboYn
         A/Uvvj0dfds97TZD3F46OOrSmFNCDFMKDAQDmN1f4QNaa1lRkEtWCIg2xgZGPtCAZl3h
         r2yQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53304zrn04NBXfgL446y3i9ZbrKviiinCpESTAZNzHndOKlcTxoW
	iZo446lHO6M5UN482jGN8Q0=
X-Google-Smtp-Source: ABdhPJwrqGxxfEv3eK4ZwHkwGgXpAb/niEJkVdHe27w6Hmb8dCrpPrlzQrOwh27pdIAOi5pBiodN8g==
X-Received: by 2002:a05:6a00:ac9:b029:2de:a06d:a52f with SMTP id c9-20020a056a000ac9b02902dea06da52fmr5467994pfl.4.1624392979621;
        Tue, 22 Jun 2021 13:16:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ed82:: with SMTP id e2ls11062955plj.2.gmail; Tue, 22
 Jun 2021 13:16:19 -0700 (PDT)
X-Received: by 2002:a17:902:d701:b029:115:d3d8:94d2 with SMTP id w1-20020a170902d701b0290115d3d894d2mr24306676ply.23.1624392979137;
        Tue, 22 Jun 2021 13:16:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624392979; cv=none;
        d=google.com; s=arc-20160816;
        b=dkC9aHUKdxe66RM/vRyMfQGOqkAtF9siu1VDpLobMCjZX9bTg1Rf5LVw3W1jxHSt+9
         7WFhXsk55gVVVrNB5czgvc5Oz2oEGgZ4QRyEc3eDK3EHDu/+lgLCJaVSNAEnfy1G0D2/
         dq2kOmH/VNhfM6DpkNRErnuoSSGnNTDOjB8GWgHD5dTu/GOPEW4wv0szyGi+YAtOK8iO
         rsGy9XyqHUwR2uaFoPpqlPSBavhigNXLFaFYFOP5tufprU6pGOxg08TtvfEKR+2tf8J7
         auEyH+6+1ZwK6zCkcHhdWrfNLHzJCIXc22g0nfflOysjwQRy58D82ki5ShEngZdOWZx1
         cjFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C767tPdPdMoTyOta+1ttzfqbko9nfCsk2O/+WzaTSOc=;
        b=r6cOGuUD8Gw5sXi124JUNXRpb4KQAdkJa5gCABDN5XJSBaDMkRXm0jucmqQzy9qK/W
         oP+sDInyDgCbm6B9S+3C7TJj1D4DHRW3suy63WxhQzlEu+Zg0/jbnSnl2cI9HU4jHr6e
         vdhszZ0vuogQ8h88lrE3Rwleq/oA1tq9XLOSBZodTC1SSczhtVJhpp8OT5CdMinFQ6BW
         MsNr94+71eWOiKJibNhKitHLh5u3Yl0T4gYCVH3ZlDGpt7i4RiXNXWtQu8jFWldL7o1Q
         289UNmFGY+szWTUd+QOS63dN5/FWAdWZtwOAgnjurtK32pLe89DzyAwzuQBkUlF+ejAF
         DWpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=brsp2b6G;
       spf=pass (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e2b as permitted sender) smtp.mailfrom=jim.cromie@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vs1-xe2b.google.com (mail-vs1-xe2b.google.com. [2607:f8b0:4864:20::e2b])
        by gmr-mx.google.com with ESMTPS id x14si29056pfq.0.2021.06.22.13.16.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Jun 2021 13:16:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e2b as permitted sender) client-ip=2607:f8b0:4864:20::e2b;
Received: by mail-vs1-xe2b.google.com with SMTP id u10so192277vsu.12
        for <kasan-dev@googlegroups.com>; Tue, 22 Jun 2021 13:16:19 -0700 (PDT)
X-Received: by 2002:a67:6948:: with SMTP id e69mr25073072vsc.26.1624392978322;
 Tue, 22 Jun 2021 13:16:18 -0700 (PDT)
MIME-Version: 1.0
References: <CAJfuBxxH9KVgJ7k0P5LX3fTSa4Pumcmu2NMC4P=TrGDVXE2ktQ@mail.gmail.com>
 <YNIaFnfnZPGVd1t3@codewreck.org> <CAJfuBxywD3QrsoGszMnVbF2RYcCF7r3h7sCOg6hK7K60E+4qKA@mail.gmail.com>
In-Reply-To: <CAJfuBxywD3QrsoGszMnVbF2RYcCF7r3h7sCOg6hK7K60E+4qKA@mail.gmail.com>
From: jim.cromie@gmail.com
Date: Tue, 22 Jun 2021 14:15:52 -0600
Message-ID: <CAJfuBxw-JUpnENT9zNgTq2wdHqH-77pAjNuthoZYbtiCud4T=g@mail.gmail.com>
Subject: Re: [V9fs-developer] KCSAN BUG report on p9_client_cb / p9_client_rpc
To: Dominique Martinet <asmadeus@codewreck.org>
Cc: kasan-dev@googlegroups.com, v9fs-developer@lists.sourceforge.net, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jim.cromie@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=brsp2b6G;       spf=pass
 (google.com: domain of jim.cromie@gmail.com designates 2607:f8b0:4864:20::e2b
 as permitted sender) smtp.mailfrom=jim.cromie@gmail.com;       dmarc=pass
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

 >
> > I had assumed the p9_req_put() in p9_client_cb would protect the tag,
> > but that doesn't appear to be true -- could you try this patch if this
> > is reproductible to you?
> >
>
> I applied your patch on top of my triggering case, it fixes the report  !
> you have my tested-by

I seem to have gotten ahead of my skis,
Im seeing another now, similar to 1st, differing in 2nd block

[    8.730061] Run /bin/sh as init process
[    9.027218] ==================================================================
[    9.028237] BUG: KCSAN: data-race in p9_client_cb / p9_client_rpc
[    9.029073]
[    9.029282] write to 0xffff888005e45ea0 of 4 bytes by interrupt on cpu 0:
[    9.030214]  p9_client_cb+0x1a/0x100
[    9.030735]  req_done+0xd3/0x130
[    9.031171]  vring_interrupt+0xac/0x130
[    9.031752]  __handle_irq_event_percpu+0x64/0x260
[    9.032381]  handle_irq_event+0x93/0x120
[    9.032950]  handle_edge_irq+0x123/0x400
[    9.033502]  __common_interrupt+0x3e/0xa0
[    9.034051]  common_interrupt+0x7e/0xa0
[    9.034608]  asm_common_interrupt+0x1e/0x40
[    9.035173]  native_safe_halt+0xe/0x10
[    9.035826]  default_idle+0xa/0x10
[    9.036299]  default_idle_call+0x38/0xc0
[    9.036845]  do_idle+0x1e7/0x270
[    9.037294]  cpu_startup_entry+0x19/0x20
[    9.037905]  rest_init+0xd0/0xd2
[    9.038354]  arch_call_rest_init+0xa/0x11
[    9.038922]  start_kernel+0xacb/0xadd
[    9.039444]  secondary_startup_64_no_verify+0xc2/0xcb
[    9.040140]
[    9.040369] read to 0xffff888005e45ea0 of 4 bytes by task 1 on cpu 1:
[    9.041283]  p9_client_rpc+0x185/0x860
[    9.041837]  p9_client_getattr_dotl+0x71/0x160
[    9.042645]  v9fs_inode_from_fid_dotl+0x21/0x160
[    9.043418]  v9fs_vfs_lookup.part.0+0x139/0x180
[    9.044059]  v9fs_vfs_lookup+0x32/0x40
[    9.044584]  __lookup_slow+0xc3/0x190
[    9.045095]  walk_component+0x1b8/0x270
[    9.045626]  link_path_walk.part.0.constprop.0+0x336/0x550
[    9.046425]  path_lookupat+0x59/0x340
[    9.046935]  filename_lookup+0x134/0x2a0
[    9.047484]  user_path_at_empty+0x6d/0x90
[    9.048145]  vfs_statx+0x79/0x1a0
[    9.048610]  __do_sys_newfstatat+0x1e/0x40
[    9.049173]  __x64_sys_newfstatat+0x4e/0x60
[    9.049755]  do_syscall_64+0x42/0x80
[    9.050233]  entry_SYSCALL_64_after_hwframe+0x44/0xae
[    9.050940]
[    9.051148] Reported by Kernel Concurrency Sanitizer on:
[    9.051893] CPU: 1 PID: 1 Comm: virtme-init Not tainted
5.13.0-rc7-dd7i-00038-g4e27591489f1-dirty #126
[    9.053185] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
BIOS 1.14.0-3.fc34 04/01/2014
[    9.054358] ==================================================================




>
> > The tag is actually reclaimed in the woken up p9_client_rpc thread so
> > that would be a good match (reset in the other thread vs. read here),
> > caching the value is good enough but that is definitely not obvious...
> >
> > --
> > Dominique

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJfuBxw-JUpnENT9zNgTq2wdHqH-77pAjNuthoZYbtiCud4T%3Dg%40mail.gmail.com.
