Return-Path: <kasan-dev+bncBD52JJ7JXILRBYPQSCRQMGQE4YGCVDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id B7537705CEC
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 04:13:55 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-2533e0cd8f2sf195355a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 19:13:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684289634; cv=pass;
        d=google.com; s=arc-20160816;
        b=UwPac9ByU+JlvhAGaQSogw+YyodIdj+aw1YVeIOJaA0JVIokKB8iX1wAV7mSshVj03
         WKqQ0/4R0pqYHGQj2ocYeMajT/4tjL6/TZgPxtAELta9w5NzTVt5z4/vMLM5Z1XW8V3Y
         RVkTq1wfTwoVs0G0IlyoszzfGNR+Z5CzIkeS2TWFmuLuWZi0F9oCiVv8EpsCDJRmdr/g
         bS49T/9ccLLDlAo8QYY96lOVzb4lShMpgY2Kc3gQu+HMLBMuzqSARZ4rjjRK9m3qp07Q
         iiXGS/bBcszEXxHvIjHgwULP9Ob8pmem72h5NkawzzZsFi/xDvmFElnXvBdSX8yetoMU
         yK3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=n8EEf2c5GK8OxxleR/epGGwfsamXNm0+ZkmWfPJeHtI=;
        b=LCGxvfplAxqGzfgu2LiNbWL4VaRKAMf7eatKnPNwkx1ivtifHxupytp0UkM0HYtNlj
         A9wHt7yIiHOO5o8YsSj/G7ZXStDClbIqlHjcde651YPXbzSYVZGkXK9ZB8UDWwE+U3Qb
         IcwE97Q0bEVI9S419XBwNWgJV/VNeQGovwwCfRkYZPlPpPHsIFbvJm1I9Ad6bsQSIzYV
         3oZH6bM5cMpbC4ROEB5ErZvGVYRCzxs3NDido/4zHS51gwGZDoF2DqL3/hO/OnHp6Rt+
         eU4wOs5tH1tNsVNNh3lSvoUSpTVIycEL4OYkxOzTq8fSAML9Smf1R8K9wm/u/j+WATA6
         oqKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=rshD+IoT;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684289634; x=1686881634;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=n8EEf2c5GK8OxxleR/epGGwfsamXNm0+ZkmWfPJeHtI=;
        b=TqdyM2zY1ejY9tcWnyrPY+Qg0fHe7xPBxZD3jQkj9zceHKbis5wI3DhG88tSg0oTZf
         9q9vSwTHuOAejpPLeRTXoBGYg6CfKsJA7Amjf2CNFLz8a6iAjFIS5KXSqEqv8D0LA7+Z
         KbzZsDef0gb87DFZNQ3E+/aF9KKJngRHWm8lvGlaVzYouUYbf5KDQazrBn3nUPpKNF+S
         HBmZj2hnY5cJSvemz+NLqLAgIgjewHIAHMlMBz3PcSlG/zE3tR1JHDXQS51VBMkU4FCJ
         uqFCQFv29qxmQUPp3FXe1ZGfbQJbN3nW9+zes0ZAZnsytTlD2zaJUq+I1HaC5ZGEbdAq
         Jj5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684289634; x=1686881634;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=n8EEf2c5GK8OxxleR/epGGwfsamXNm0+ZkmWfPJeHtI=;
        b=OrDBdKCEZ7/abPXfzblnd3zuIZHqMMHxhOlM0duqnuK2qgs6n84zaQ9DasiQQmhyfe
         Jx+PeOaP2E8lgZBncQFf25jsqKxN9tamHPffs1bmwt3AkQNePgIuKd96WOfgb5fEsh4Z
         C9ib+Ck40peygY9DCPt7Qb3v8gFdm8hBECj7QziKGnV4QeGmPWQc2n7/f2zI6r7jzQ3T
         l8BDSpx5g/89RJ+AUfI67IZaDfg/Xt/0fLZj+fL/7Tft3fKh7goDGYCAV+ayypQJGDj/
         rqJvn6EYBv2aFxYugrtiLkTz1xjTGA+UlQF32Am2J3PnG+0sa1UMRn8cJcaWIgiOr8FY
         jTcQ==
X-Gm-Message-State: AC+VfDyr1UupG3uesGICJW5ramoDGT2WWOvp8B9DLBuDACTcgojHjloo
	5MlAih3GHfx4JEkOpy0xOuI=
X-Google-Smtp-Source: ACHHUZ5CtcWrD5sG9SF1T5lZmA8aH6oNM+YrFS3T7cyGhj8agUYY/Xl7/kAWa4WoNyRf98oRjmp3+Q==
X-Received: by 2002:a17:902:e5c1:b0:1a6:c110:902a with SMTP id u1-20020a170902e5c100b001a6c110902amr12762583plf.5.1684289633716;
        Tue, 16 May 2023 19:13:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:da05:b0:253:2806:8db5 with SMTP id
 e5-20020a17090ada0500b0025328068db5ls597299pjv.0.-pod-prod-05-us; Tue, 16 May
 2023 19:13:52 -0700 (PDT)
X-Received: by 2002:a17:902:b946:b0:1a6:b23c:3bf2 with SMTP id h6-20020a170902b94600b001a6b23c3bf2mr39696434pls.10.1684289632084;
        Tue, 16 May 2023 19:13:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684289632; cv=none;
        d=google.com; s=arc-20160816;
        b=eTQyfr2m7XZZaCRzBNg/cPfsEqjdNpJEpgUToxrIVzEV0KZ4gi4BLxuBG0IMjfJXQH
         ye05FwXPxUt54eQYGIfKhIgJev/alfZmW22keKzvSuS9pfabc0pkzee2sbOOnXX2tPkq
         bilkiutM6PPwntZaJvIGXf4Kta+nuE0g6ScbqvUwUB+i5wrz1ZT2hgH+OVUyopNorayx
         EUVGvxvYderiOhdD0sJBH9Xsbf8YxxzsBICOp3pGltVAqKNT+r4yK3YSJjniw7LfwPKW
         b7wVDdBwnHlfNCUl6TKaTb/8FVXCdw5WZ+ZDei5tJnJoU5n7g04VP1VUlbDQnAYMHrbS
         tj0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=J9H9xxY0IRCExY9H0nSI5ZkiuSsdqps+Roz6yPP7WfA=;
        b=mB35LWZAHv56Syj02Sk1/46so3uyIXXLjwTCfmT5GUYem7OEskdF/PZ4iuw7NIDhX2
         Gat9z5caTLyz8IMnf8qpxlYBhdKD9Avqz+kSwHewiJdGZKYHUz0vGHJ61EaMDH3iqY9i
         QNI2tHISamt0QIRmrD6utqY4wN3vfgA6vODFpWP04N8CnxNPKAO/UeA3V2GDb25o87Er
         HyNPw1EIax89qFY7m4mh8WQJxeUvjab19WS/Wm2AScSTB7USHALDQgshFA605hzG4VzE
         Dby/YOiGKHKvi8B6WxaukWJqeW8fE8cebdD3FLR/X4J6vo1lAL336v95trrkXVe8r0dW
         qn+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=rshD+IoT;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x134.google.com (mail-il1-x134.google.com. [2607:f8b0:4864:20::134])
        by gmr-mx.google.com with ESMTPS id kl8-20020a170903074800b0018712ccd6e0si961407plb.2.2023.05.16.19.13.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 May 2023 19:13:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::134 as permitted sender) client-ip=2607:f8b0:4864:20::134;
Received: by mail-il1-x134.google.com with SMTP id e9e14a558f8ab-3330afe3d2fso30155ab.1
        for <kasan-dev@googlegroups.com>; Tue, 16 May 2023 19:13:52 -0700 (PDT)
X-Received: by 2002:a05:6e02:1523:b0:335:a48:f668 with SMTP id
 i3-20020a056e02152300b003350a48f668mr79515ilu.15.1684289631318; Tue, 16 May
 2023 19:13:51 -0700 (PDT)
MIME-Version: 1.0
References: <20230512235755.1589034-1-pcc@google.com> <20230512235755.1589034-2-pcc@google.com>
 <7471013e-4afb-e445-5985-2441155fc82c@redhat.com> <ZGLLSYuedMsViDQG@google.com>
 <efd5fb89-4f60-bee1-c183-5a9f89209718@redhat.com>
In-Reply-To: <efd5fb89-4f60-bee1-c183-5a9f89209718@redhat.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 May 2023 19:13:40 -0700
Message-ID: <CAMn1gO55p_Vz0wrSqHxJ0nw_bncEyja8=mBedY29=8UdC3ejww@mail.gmail.com>
Subject: Re: [PATCH 1/3] mm: Move arch_do_swap_page() call to before swap_free()
To: David Hildenbrand <david@redhat.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, 
	=?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>, 
	=?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?= <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	=?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>, 
	=?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?= <casper.li@mediatek.com>, 
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>, vincenzo.frascino@arm.com, 
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org, eugenis@google.com, 
	Steven Price <steven.price@arm.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=rshD+IoT;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::134 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Tue, May 16, 2023 at 5:40=E2=80=AFAM David Hildenbrand <david@redhat.com=
> wrote:
>
> On 16.05.23 02:16, Peter Collingbourne wrote:
> > On Sat, May 13, 2023 at 05:29:53AM +0200, David Hildenbrand wrote:
> >> On 13.05.23 01:57, Peter Collingbourne wrote:
> >>> Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") mo=
ved
> >>> the call to swap_free() before the call to set_pte_at(), which meant =
that
> >>> the MTE tags could end up being freed before set_pte_at() had a chanc=
e
> >>> to restore them. One other possibility was to hook arch_do_swap_page(=
),
> >>> but this had a number of problems:
> >>>
> >>> - The call to the hook was also after swap_free().
> >>>
> >>> - The call to the hook was after the call to set_pte_at(), so there w=
as a
> >>>     racy window where uninitialized metadata may be exposed to usersp=
ace.
> >>>     This likely also affects SPARC ADI, which implements this hook to
> >>>     restore tags.
> >>>
> >>> - As a result of commit 1eba86c096e3 ("mm: change page type prior to
> >>>     adding page table entry"), we were also passing the new PTE as th=
e
> >>>     oldpte argument, preventing the hook from knowing the swap index.
> >>>
> >>> Fix all of these problems by moving the arch_do_swap_page() call befo=
re
> >>> the call to free_page(), and ensuring that we do not set orig_pte unt=
il
> >>> after the call.
> >>>
> >>> Signed-off-by: Peter Collingbourne <pcc@google.com>
> >>> Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> >>> Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f84104=
9b8c61020c510678965
> >>> Cc: <stable@vger.kernel.org> # 6.1
> >>> Fixes: ca827d55ebaa ("mm, swap: Add infrastructure for saving page me=
tadata on swap")
> >>> Fixes: 1eba86c096e3 ("mm: change page type prior to adding page table=
 entry")
> >>
> >> I'm confused. You say c145e0b47c77 changed something (which was after =
above
> >> commits), indicate that it fixes two other commits, and indicate "6.1"=
 as
> >> stable which does not apply to any of these commits.
> >
> > Sorry, the situation is indeed a bit confusing.
> >
> > - In order to make the arch_do_swap_page() hook suitable for fixing the
> >    bug introduced by c145e0b47c77, patch 1 addresses a number of issues=
,
> >    including fixing bugs introduced by ca827d55ebaa and 1eba86c096e3,
> >    but we haven't fixed the c145e0b47c77 bug yet, so there's no Fixes:
> >    tag for it yet.
> >
> > - Patch 2, relying on the fixes in patch 1, makes MTE install an
> >    arch_do_swap_page() hook (indirectly, by making arch_swap_restore()
> >    also hook arch_do_swap_page()), thereby fixing the c145e0b47c77 bug.
> >
>
> Oh. That's indeed confusing. Maybe that should all be squashed to have
> one logical fix for the overall problem. It's especially confusing
> because this patch here fixes the other two issues touches code moved by
> c145e0b47c77.

Maybe. It can sometimes be hard to reconcile "one logical change per
patch" with "bug requires more than one logical change to fix" though.
Fortunately in this case I think we have an approach that fixes the
bug in one logical change, with some followup patches to clean things
up.

> > - 6.1 is the first stable version in which all 3 commits in my Fixes: t=
ags
> >    are present, so that is the version that I've indicated in my stable
> >    tag for this series. In theory patch 1 could be applied to older ker=
nel
> >    versions, but it wouldn't fix any problems that we are facing with M=
TE
> >    (because it only fixes problems relating to the arch_do_swap_page()
> >    hook, which older kernel versions don't hook with MTE), and there ar=
e
> >    some merge conflicts if we go back further anyway. If the SPARC folk=
s
> >    (the previous only user of this hook) want to fix these issues with =
ADI,
> >    they can propose their own backport.
>
> Sometimes, it's a good idea to not specify a stable version and rather
> let the Fixes: tags imply that.

Yeah, but sometimes it's hard to say which way would be more
efficient. Either we spend time discussing why the version is
necessary or Greg spends time trying to apply patches to the wrong
trees because I wasn't more explicit...

Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMn1gO55p_Vz0wrSqHxJ0nw_bncEyja8%3DmBedY29%3D8UdC3ejww%40mail.gm=
ail.com.
