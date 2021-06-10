Return-Path: <kasan-dev+bncBCUY5FXDWACRB4VCRGDAMGQEE3HOTYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A7333A3281
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 19:52:50 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id v2-20020a7bcb420000b0290146b609814dsf3371929wmj.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 10:52:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623347570; cv=pass;
        d=google.com; s=arc-20160816;
        b=SMdapw1iIvzfG12gJZQH8M9XvxibZS4h4bUU6cgBK5bST8qaBSeKxuAFjA88414fcO
         OlEEBMM96J/M5RLua6WsxJRNURtBSJNq74x1HuFI7avxKQd1e+1sRQm6J1mgMHt4lSBz
         +tX64wz4PP4vQXP8G3KldR4zf5uYb3/B/b2DskNkE8TLVZBgZqcyiUY1fXLM+r10A0Yz
         qugeDPYOOJvzrXTmf6ZUbIlUP1huDZCbPH1w7FqDdAUNEHYt7ZBlSbYhPeas7K4N1p7s
         8P0TNAFgVl4yoICfhonkCjS6RmlWkov9k/yq1oaUh6xOt+t6jt+lFLvua04ZnZwxlXU/
         ccrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=iuxad+Eyl204QpdOw0veijJ944bvqcg7hqeHvZ116Mc=;
        b=zoQDvzCOWLMQvSHwVdmQWWiW5xUNy1YAGiKTYgIFEbZFidwoF5Mn46t8ZVmtwo+ldN
         2yWpFNCuCJq2mFB0DIzYcrmKBl/rmY6IU9CIPFKBFEyVBt0UwN5pBtx9RDTGs05nQyI1
         0yaKeiNroZuYYiGixycSs5O5hnE8DqrduaccidV2ox/gA2fUb44oAnjAOmrDCAKnCXry
         OMqZBaRgILjzTGUw4vAin3XAbBb3IBQwH5B70gIw3C2vIzkVHsMzG1+Oo1rjN4RnWKDZ
         SkkH36nMnXa8i/ZDxoAksKsxaJHSxA10lpiEd78bSLrptU2pBzDtPs2Lm9zz1nq7Ez+t
         SZKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=j9utiUZQ;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iuxad+Eyl204QpdOw0veijJ944bvqcg7hqeHvZ116Mc=;
        b=iJhKZfojjM9FBTk34tmOXRSvA7P+zVB8Nj8QVfP5eodo+VEOktCAtO40wvK+dmZ0rI
         VVxENCnaMGNCywffLzLniGbCCjaRgztoJgoBs0VKQcVKB9wgfw8oM930lU4jZ9L1VXR6
         KW8kqkJydQuO2nj9GqrBF6bH9Tt0ZxPmOHToEyR8fOBAiIjqNBEAIDI2elBR+qVBAGZK
         ywUq7H6cX4ImyzdHyVzeVgwEedO1DvmD6X7gM0ogUxO0JMps9j82mLPB8uwE5IOvtXeS
         UdMBwiOAMzWgV/jPwnkBvkOEyip7SSz+bWELWXOgFYpp5WOErz7Rb+sPeaekhCV6JWT/
         GIFQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iuxad+Eyl204QpdOw0veijJ944bvqcg7hqeHvZ116Mc=;
        b=ivFKo8CoaLRi4Wyuj9ab5g4or4cKLXMtZ2CD2slOOPJBg2zYddtMjnqdBbmGVZESjM
         wn5c0KqU7nZusTeA16J0nU3d3fIg9pUo84RGw0mi4YfGGcOWoB4ETg7lhoAo3FkLj10m
         pkrnT8FcL6KAhl5RxL6Z0VvNtHgmUcxGyi9caKEJHZSApINa2yVsNIK+IaXBmgEIuSC+
         I4tIs5bDhvz07gY7U4NK8EJ5CTS437Z33TTFZZ0YNiC/YmQaqFe0Ir5bND1WCMlS0C9E
         f3xkSka4WLrp4rpI/xCkQiuCZrv5F2VfOnALzv5c2a6+AU1JHhQB5DezwUXfrH4g2sz8
         h0ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iuxad+Eyl204QpdOw0veijJ944bvqcg7hqeHvZ116Mc=;
        b=AQipMeAEjfoVFRpWjcrIxb1H/WGYS60GS+f8A2xKI9pLEkDN/us5kwbswS7+c4u2q2
         qOLftAW2/iJnbfidB+REpviXYVmljw7ZU4qeYuQK9HeueOTb5TeAbFrJPSUSAZY7uJ/e
         eLouYi/p19mW0gSb95Cb33aVzGJTmavJDLlmsPYW8sHPq4vQP4e1/+vCch9LVhQftRvV
         1J6rF3ZKQT1f3IXKtQwGkI1pbxRaJ+GFAcc9FsyLQ0kTgZMnXvsnbf+ZyEto72lT27bK
         VGpjZvp1ZDKvJ4Q1sTnlsTIBs+VdehauhHMD0fEY3YXKF8Zcj5dnChLhnjsfcjH4/F8b
         PbPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530IgrZ9PxJjWHmTfNALTiruGZCainHlGINPyIUMyPhEQb/OI8JD
	dM58SC188ydAukB6RipvShY=
X-Google-Smtp-Source: ABdhPJxCc27E2cIqLYCvjNCY5KwxOUOnPLvMUqahsRbyk9SFkIq6QoSXs4mbJTDSLFptfOEP/i3j0g==
X-Received: by 2002:a05:600c:4f4a:: with SMTP id m10mr42551wmq.51.1623347570336;
        Thu, 10 Jun 2021 10:52:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eac1:: with SMTP id o1ls2229418wrn.2.gmail; Thu, 10 Jun
 2021 10:52:49 -0700 (PDT)
X-Received: by 2002:adf:fc90:: with SMTP id g16mr6760551wrr.183.1623347569430;
        Thu, 10 Jun 2021 10:52:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623347569; cv=none;
        d=google.com; s=arc-20160816;
        b=bsrQa2mQQPGLT8gArOUR25xaR3R6beskVyQZDsZIn50xuUSgToeXTOUOqckhmzh5Up
         Oc8VyD5415S7PApRJ4VSeDSZJqL44ARKJCVes2N3Upy31GI8jXyYXJK9BPsc5U1Y17wz
         hbqihgi5zbe8c2U3nXpJgbKKM/0tiVNqY9ClZcgSyje4/LR99MgaUeoXdtuLYZ4NLZbS
         rrd8tWDf6RtTSEI7dnSxEikknT0fjkPvhktqrjyTDRzL1mb4J+FuqysvQfarhmAT1HG/
         7yrbl5FMkZsvERQbcHt0GxwaB7o0fKDdzlqPPa9HFVpF4b9RdO/JAuHkiZ+EzblufWcQ
         I2Ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=on0Tnjo9EX+wZkS0PcGQkLK+8ozdHMxgRM2ZPf0mD60=;
        b=B/79xHHpun/6NpC6+2daRmUQuqTrOMdscr5uhYPXU3qqgyGvoWd+WezZBmYK+TdwYo
         m2k6kMdOX45+kAkk05482x3DFu3GS3GVlJvY2YPeZ71rDIvEU6a0uU7BERyTuNHhYiNu
         8f3SCRqOfeBckbxMZTi3I0r6ILIqJd3ibrlj28HS/vUaP21RISRlqMCTR6eRkZbAvn4S
         Z/dRlEIA1IBGY3WT03qd3mZphSYrZ+zySvGkYtkJZIg/t42pJ1G41IUQLWRYCxVpSWL8
         H9r3fVODaFRGEYSnnxDKkUAZSsm6kHrDRlhnsAmcgOtQhDnECRCThVyEu21ercEysXuj
         hRHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=j9utiUZQ;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x22d.google.com (mail-lj1-x22d.google.com. [2a00:1450:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id t1si132162wrn.4.2021.06.10.10.52.49
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Jun 2021 10:52:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::22d as permitted sender) client-ip=2a00:1450:4864:20::22d;
Received: by mail-lj1-x22d.google.com with SMTP id bn21so6124414ljb.1;
        Thu, 10 Jun 2021 10:52:49 -0700 (PDT)
X-Received: by 2002:a2e:b5c8:: with SMTP id g8mr3170497ljn.204.1623347568936;
 Thu, 10 Jun 2021 10:52:48 -0700 (PDT)
MIME-Version: 1.0
References: <20210602212726.7-1-fuzzybritches0@gmail.com> <YLhd8BL3HGItbXmx@kroah.com>
 <87609-531187-curtm@phaethon> <6a392b66-6f26-4532-d25f-6b09770ce366@fb.com>
 <CAADnVQKexxZQw0yK_7rmFOdaYabaFpi2EmF6RGs5bXvFHtUQaA@mail.gmail.com>
 <CACT4Y+b=si6NCx=nRHKm_pziXnVMmLo-eSuRajsxmx5+Hy_ycg@mail.gmail.com>
 <202106091119.84A88B6FE7@keescook> <752cb1ad-a0b1-92b7-4c49-bbb42fdecdbe@fb.com>
 <CACT4Y+a592rxFmNgJgk2zwqBE8EqW1ey9SjF_-U3z6gt3Yc=oA@mail.gmail.com>
 <1aaa2408-94b9-a1e6-beff-7523b66fe73d@fb.com> <202106101002.DF8C7EF@keescook>
In-Reply-To: <202106101002.DF8C7EF@keescook>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Thu, 10 Jun 2021 10:52:37 -0700
Message-ID: <CAADnVQKMwKYgthoQV4RmGpZm9Hm-=wH3DoaNqs=UZRmJKefwGw@mail.gmail.com>
Subject: Re: [PATCH v4] bpf: core: fix shift-out-of-bounds in ___bpf_prog_run
To: Kees Cook <keescook@chromium.org>
Cc: Yonghong Song <yhs@fb.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Kurt Manucredo <fuzzybritches0@gmail.com>, 
	syzbot+bed360704c521841c85d@syzkaller.appspotmail.com, 
	Andrii Nakryiko <andrii@kernel.org>, Alexei Starovoitov <ast@kernel.org>, bpf <bpf@vger.kernel.org>, 
	Daniel Borkmann <daniel@iogearbox.net>, "David S. Miller" <davem@davemloft.net>, 
	Jesper Dangaard Brouer <hawk@kernel.org>, John Fastabend <john.fastabend@gmail.com>, 
	Martin KaFai Lau <kafai@fb.com>, KP Singh <kpsingh@kernel.org>, Jakub Kicinski <kuba@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, Network Development <netdev@vger.kernel.org>, 
	Song Liu <songliubraving@fb.com>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	nathan@kernel.org, Nick Desaulniers <ndesaulniers@google.com>, 
	Clang-Built-Linux ML <clang-built-linux@googlegroups.com>, 
	linux-kernel-mentees@lists.linuxfoundation.org, 
	Shuah Khan <skhan@linuxfoundation.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Kernel Hardening <kernel-hardening@lists.openwall.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=j9utiUZQ;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::22d as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Jun 10, 2021 at 10:06 AM Kees Cook <keescook@chromium.org> wrote:
>
> > > I guess the main question: what should happen if a bpf program writer
> > > does _not_ use compiler nor check_shl_overflow()?
>
> I think the BPF runtime needs to make such actions defined, instead of
> doing a blind shift. It needs to check the size of the shift explicitly
> when handling the shift instruction.

Such ideas were brought up in the past and rejected.
We're not going to sacrifice performance to make behavior a bit more
'defined'. CPUs are doing it deterministically. It's the C standard
that needs fixing.

> Sure, but the point of UBSAN is to find and alert about undefined
> behavior, so we still need to fix this.

No. The undefined behavior of C standard doesn't need "fixing" most of the time.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAADnVQKMwKYgthoQV4RmGpZm9Hm-%3DwH3DoaNqs%3DUZRmJKefwGw%40mail.gmail.com.
