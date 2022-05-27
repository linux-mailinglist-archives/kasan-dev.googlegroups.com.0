Return-Path: <kasan-dev+bncBCMIZB7QWENRBN47YOKAMGQENCKPZRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5514C53633E
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 15:18:48 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id e3-20020a2e9303000000b00249765c005csf1273489ljh.17
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 06:18:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653657527; cv=pass;
        d=google.com; s=arc-20160816;
        b=XwABhsd8B/rsl/FuwXvOjGeyN9uzMkFV1Rmt7GczTNGOmU00NMzlEnpfO9ia2I1nMG
         1lqviK47LWJ/D+47hx9/3uwYa/Ru9+Bavrdc8DH9n0pAHwWI7KjxVYb2XF1lMaualWux
         k+w0GZ6+OFjiKWyA718J0xBwCnDffgUBL2GTuVhSBa5pvDpAytteZpsQ3puThJVd5whj
         FRQzWknLXQdImJs+Jrtm97gyTvtLS4q6iV/BT1jvMLHiDGA0aK2uu9K1eb+6qMtuyTyl
         2sXgfqF3oCoG4M5cafHDz3wqTkigEB8Bbw0D+HW0EX05E9q1j93MMesFwefMkoVEKkLI
         W36A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uK+goGmhVp/JH7ojnadT3W9gkXz1hmDKzKifcwEul/o=;
        b=zMlpBzuLfQgI3VkXqZR/aidOYLanuwUtHvB7P4kbZronpi9A1j2pInJBnvyFQ5dp3d
         ZgfaS0aUe92vM0VOFjoKYFDUJ/3ehtNB4LyfMX8fGOvMzCJzMfniMtSUxNOzi9Mxokvi
         OkNrAkdhFUEgrrRwWTr8NAYJSjHhnFoLGYUh2i0L9DzDbD7vWvlwqXbQPZHNOs2nUjeJ
         HO1TG+VldaRUETDBE3DnQXet4TJmK+FsMvjPkLyDWFVyrByVZuyAgBwEtNU4w4ipUxpW
         jK1+1GKEHShx98/ZWUDBa62riYCNnhWR2TKogdiaGlSFCjlU/My4O+S7CjXXw8wiXcCE
         ehfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qxI8FKs5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uK+goGmhVp/JH7ojnadT3W9gkXz1hmDKzKifcwEul/o=;
        b=lM9DLE+DIP92cdpDqSZDSGVejthho2/aOuDoa5f/OliPHMx1Fnrqp/V26MkQttrPgj
         QRpLuIFLFuwrFxQbOxp1oEc1moFsFCBN8fKPP8jC3WhXu5H4+WyTdtbWw4ahX+9EBlAR
         YKvFzAhxGSJbYJT3caKtnzoUiLbgpaIECVQw3M7g5hzDmHoZ3sqILVrD5S/jNibGLVWp
         a2RZCvgQHt1YMhBE1xNuFfhT/fJoGbLTekLFtQ+6sv+XeiOwtr5S5ed9IWQcK6UxHFmH
         Xa11X/hRii9xXEBwCyi1TSdebKvXjt6Gth+ZtWmpPNIw0T7ajWr6udm/DLbKYFsy48gA
         WWyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uK+goGmhVp/JH7ojnadT3W9gkXz1hmDKzKifcwEul/o=;
        b=79ZymjsCfh7MwymM4hUyW/S5QmyTOzijphmMZQkys71y+lUgxcybpee/8SfDfdOpua
         7l7lkl6K7tCaGOmyvn6Vma9wG4uJ+SSWmwrHUNiEO9CQsHCP8USIK7E+bgJehmuz9nGM
         sd9D/XG7itjPuhKn95D+P++b9oycDe4kxK7eCM1vvwnYyEJVohP6Gd/mBialQmjmdsnt
         TtNDoSFMKnsZ4V6E1zNCyqxy76OfZgJygqQfXtidqNHKpO8zERrYvBDhEr2YN/tDT3Pq
         pAP0bH2GCMqc9PX3I1Gtl5qFF44gZDM+ulPm+biVB0bkf/iA50OQL2Fsi+Toy8rjjqGq
         TbIw==
X-Gm-Message-State: AOAM530zLCG9TAD8lMU+IP6NzUNnnvErafY2xGMlxRAAORumVH66X8m3
	wmnkngMb1UFEuHPGLT+B9Fw=
X-Google-Smtp-Source: ABdhPJxrEHOdztIncCHq7k3sFGPowsYti/AQ7V1Rgg7mVs8apFaYqVOIkZsQizDIKH7oFsMzmBrxSw==
X-Received: by 2002:a05:6512:3e1e:b0:477:cd0b:b1ad with SMTP id i30-20020a0565123e1e00b00477cd0bb1admr26225425lfv.591.1653657527622;
        Fri, 27 May 2022 06:18:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:10cb:b0:478:7256:822a with SMTP id
 k11-20020a05651210cb00b004787256822als1204172lfg.3.gmail; Fri, 27 May 2022
 06:18:46 -0700 (PDT)
X-Received: by 2002:a05:6512:ad6:b0:478:68c8:dd73 with SMTP id n22-20020a0565120ad600b0047868c8dd73mr19157939lfu.296.1653657526413;
        Fri, 27 May 2022 06:18:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653657526; cv=none;
        d=google.com; s=arc-20160816;
        b=xDdXAVib96ZCZQaQqMCzsxJgDz9r8nDu5ZADQaRZ/MWonZ2VACEUnf7IAYlRADg2Fd
         vK6ig/d8ps8Po2dKMPdlTdY8X2ChBQ5hFV/UcF+V9KKP3JEeSvdeTrSIph2gjMJvqx7h
         LzzjYcJwih2uvZeIwQhTrti+8+bDTJ8S7CplBD4DVFXDI6IShTd9Wcf5ArslDi8YYAZI
         nEFzabAD2eSNZX7u2LZceAm56/AYrlumhTrxqstyLSrS0+Ve0Unn55hoNUXEKy8xbzVN
         A8rOfy5NS/ae3OC/jrQOoP+Pfo7RGEAJCFgPu2ExEzqXtRyTJvuglK71zUclu3NAuIDv
         R5/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G/ubRkGNzoAnaLrfe1Abk/gSZHaSvaWBOlXMLf4fhxE=;
        b=Ndoen/Vu40FhTM73COi1AnDZZJbDJ0BTuPjK5eOqFR3NZC4eo/4o5MpPr0nKT5du1Q
         98+sHsyPHBr4UiocSqrNtp9heZTo7TUXoAT4mvLChTsRsorI410cAdETpIb7lKSPTUSp
         9gsr4SVO4h2KXuCMylVt+xZBr+AkTR+1A847dnBf+2gb0IBgveXu0MMZr5tU7MYB030X
         169evX2+ulJ3I0QG2cVQ4sL+1SaT/lDzHv7BQlm7J15kiBNEYZmb6B5Nwxmc9p6uEAsR
         JyRmxVBmM+S97f9i4HkT1bOreDPRt8uXnPXxEVmvqpERGNJSZ3NoHBig8CkolTI0kHRk
         vzzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qxI8FKs5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id o21-20020ac24e95000000b0047878a17143si199627lfr.8.2022.05.27.06.18.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 May 2022 06:18:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id g12so4847306lja.3
        for <kasan-dev@googlegroups.com>; Fri, 27 May 2022 06:18:46 -0700 (PDT)
X-Received: by 2002:a05:651c:1502:b0:253:ed7e:5778 with SMTP id
 e2-20020a05651c150200b00253ed7e5778mr14018377ljf.47.1653657525877; Fri, 27
 May 2022 06:18:45 -0700 (PDT)
MIME-Version: 1.0
References: <20220525111756.GA15955@axis.com> <20220526010111.755166-1-davidgow@google.com>
 <e2339dcea553f9121f2d3aad29f7428c2060f25f.camel@sipsolutions.net>
 <CACT4Y+ZVrx9VudKV5enB0=iMCBCEVzhCAu_pmxBcygBZP_yxfg@mail.gmail.com> <6fa1ebe49b8d574fb1c82aefeeb54439d9c98750.camel@sipsolutions.net>
In-Reply-To: <6fa1ebe49b8d574fb1c82aefeeb54439d9c98750.camel@sipsolutions.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 May 2022 15:18:34 +0200
Message-ID: <CACT4Y+bhBMDn80u=W8VBbn4uZg1oD8zsE3RJJC-YJRS2i8Q2oA@mail.gmail.com>
Subject: Re: [RFC PATCH v3] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: David Gow <davidgow@google.com>, Vincent Whitchurch <vincent.whitchurch@axis.com>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Brendan Higgins <brendanhiggins@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-um@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qxI8FKs5;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::231
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, 27 May 2022 at 15:15, Johannes Berg <johannes@sipsolutions.net> wrote:
>
> On Fri, 2022-05-27 at 15:09 +0200, Dmitry Vyukov wrote:
> > > I did note (this is more for kasan-dev@) that the "freed by" is fairly
> > > much useless when using kfree_rcu(), it might be worthwhile to annotate
> > > that somehow, so the stack trace is recorded by kfree_rcu() already,
> > > rather than just showing the RCU callback used for that.
> >
> > KASAN is doing it for several years now, see e.g.:
> > https://groups.google.com/g/syzkaller-bugs/c/eTW9zom4O2o/m/_v7cOo2RFwAJ
> >
>
> Hm. It didn't for me:

Please post a full report with line numbers and kernel version.

> > BUG: KASAN: use-after-free in ieee80211_vif_use_reserved_context+0x32d/0x40f [mac80211]
> > Read of size 4 at addr 0000000065c73340 by task kworker/u2:1/17
>
> Yes.
>
> > CPU: 0 PID: 17 Comm: kworker/u2:1 Tainted: G           O      5.18.0-rc1 #5
> > Workqueue: phy0 ieee80211_chswitch_work [mac80211]
> > Stack:
> >  60ba783f 00000000 10000c268f4e 60ba783f
> >  60e60847 70dc9928 719f6e99 00000000
> >  71883b20 60bb0b42 60bb0b19 65c73340
> > Call Trace:
> >  [<600447ea>] show_stack+0x13e/0x14d
> >  [<60bb0b42>] dump_stack_lvl+0x29/0x2e
> >  [<602ef7c0>] print_report+0x15d/0x60b
> >  [<602efdc0>] kasan_report+0x98/0xbd
> >  [<602f0cc2>] __asan_report_load4_noabort+0x1b/0x1d
> >  [<719f6e99>] ieee80211_vif_use_reserved_context+0x32d/0x40f [mac80211]
>
> This is the user, it just got freed during a function call a few lines
> up.
>
> > Allocated by task 16:
> >  save_stack_trace+0x2e/0x30
> >  stack_trace_save+0x81/0x9b
> >  kasan_save_stack+0x2d/0x54
> >  kasan_set_track+0x34/0x3e
> >  ____kasan_kmalloc+0x8d/0x99
> >  __kasan_kmalloc+0x10/0x12
> >  __kmalloc+0x1f6/0x20b
> >  ieee80211_alloc_chanctx+0xdc/0x35f [mac80211]
>
> This makes sense too.
>
> > Freed by task 8:
> >  save_stack_trace+0x2e/0x30
> >  stack_trace_save+0x81/0x9b
> >  kasan_save_stack+0x2d/0x54
> >  kasan_set_track+0x34/0x3e
> >  kasan_set_free_info+0x33/0x44
> >  ____kasan_slab_free+0x12b/0x149
> >  __kasan_slab_free+0x19/0x1b
> >  slab_free_freelist_hook+0x10b/0x16a
> >  kfree+0x10d/0x1fa
> >  kvfree+0x38/0x3a
> >  rcu_process_callbacks+0x2c5/0x349
>
> This is the RCU callback.
>
> > Last potentially related work creation:
> >  save_stack_trace+0x2e/0x30
> >  stack_trace_save+0x81/0x9b
> >  kasan_save_stack+0x2d/0x54
> >  __kasan_record_aux_stack+0xd5/0xe2
> >  kasan_record_aux_stack_noalloc+0x12/0x14
> >  insert_work+0x50/0xd7
> >  __queue_work+0x805/0x95c
> >  queue_work_on+0xba/0x131
> >  call_usermodehelper_exec+0x242/0x361
> >  kobject_uevent_env+0xe46/0xeaf
> >  kobject_uevent+0x12/0x14
> >  driver_register+0x37e/0x38d
> >  pcie_port_service_register+0x19d/0x1a5
>
> This stuff is completely unrelated.
>
> > The buggy address belongs to the object at 0000000065c73300
> >  which belongs to the cache kmalloc-192 of size 192
> > The buggy address is located 64 bytes inside of
> >  192-byte region [0000000065c73300, 0000000065c733c0)
> >
>
> and that's it?
>
> johannes
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6fa1ebe49b8d574fb1c82aefeeb54439d9c98750.camel%40sipsolutions.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbhBMDn80u%3DW8VBbn4uZg1oD8zsE3RJJC-YJRS2i8Q2oA%40mail.gmail.com.
