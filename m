Return-Path: <kasan-dev+bncBCTYRDEG7MGBBR7FSGAQMGQE4I4G3AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 59A473174CD
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 00:56:56 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id s29sf1905627otg.11
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Feb 2021 15:56:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613001415; cv=pass;
        d=google.com; s=arc-20160816;
        b=r7kLrkL38ShSl+HzwExJS14pZ8KeGkFngti0p3nhwHWRpouNmKq337tBA9AoBdStUH
         0JsdHCDy73jJyFrWRGUODZx3GPMtm2wJOKrGkUFoxeUvJWKVcqaDlIq/ERAM9jkmSFS1
         rfpMYpWRLcRTBZHgIKMPGDDQLtWnE/QIxPek3I8Ln3rVyD4DI1DIkRICBUg8lw7OYw5Y
         WhJNiSnwpu5a8z5VpZEZI77Meo3UZc70vwjTEVG5h1eAij4DNkdgjuj4k4cydnVwdi7I
         kcpvu0LwvBvLg/luS3ERIFB/UGzB/qUCTiJvWV63oJ04h/NS3fSpziMRH67NHwZlALRn
         6zaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=uDT7v5EgMDXpWmJZb7OIrcHi4ELxSVTwCk95a08JWc4=;
        b=kXahyOCunc9b7RFW1WlLn1dotdIRLSni2OaKz2d1esdZXVbxkjB+kTWeVGHC71X5iw
         o+2ikDp7LlpS83OSDZi0/viY0uc/eRnC1E3hVhsgQrljmTMXQNgQCl3+k5LnHbiPeMUO
         ay5/z6PO6sjXJ/4wvVH70wAmjUMGvHjCdhogf1aZakMCa9+ep8K5ay8HTraUwIcd8q7b
         uFSnTHkBgJP0B0Ew4FQl001FqhW3FMVl7RVKpDEZt/WvD+XDSTPd9r/iD4Ggv/g096GT
         wITEQ62lLJFOBTjpSm4004yZq8golL3aG4tWh0F7oKHclFw3dZ50l8RcU3luhyXeRpAs
         2Arg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=pJPqASHZ;
       spf=pass (google.com: domain of andrii.nakryiko@gmail.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=andrii.nakryiko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uDT7v5EgMDXpWmJZb7OIrcHi4ELxSVTwCk95a08JWc4=;
        b=iqQyAgvKLNSckhSB/ggI+E6N6l4KTaeGAVOn6CyOCZBJsSF+6bTWRETSMMmxW/7itQ
         dJcoegv8BpAbyc6MN9hji2LAgyAMf1Cp/I2U4rynfVjSkS+Cjf0E4cD/XJgypH9L7ORn
         gsAzM0TQd0LSzxRX/rVFpmJq8AcBHy3pap1hSRyCizxt23qasrS+luUhLPflLzQ1M30+
         3a0sR9ujKULloo6N/z8Tw6srX9MK96h0o6CgqEsDSYs0ZVlqcmdso2DgEP0DJIhXwm+U
         F51E/EjRY734X4X7yZX+VC01p2aJlQi42tlhK0Dit5KkIgor7YsrOXfhkrdrJJE8xqzO
         lDAQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uDT7v5EgMDXpWmJZb7OIrcHi4ELxSVTwCk95a08JWc4=;
        b=Oh/OAKtglR5j/opO1vLXhvHvuAYGXNOChVnbJrLczMejiU0HZgLqbLUB51SUFfgXgb
         ePS1kcnsInrUlBuW56hjepBaHR5o+K2T4f6dxwx/SZ4NKIbFcYBNWX7/FJdDN25Vk7z8
         5rFhCdUstQT4fFz5i7E2ur2CEwLtw5XE+aV4tqJcDoRtoWrWoFUUZQrhgNcDMNSco0p9
         10be5w56yl64w/aX59sjgUKvQXnaHQe1qI+rfZKMdV6cmAnBgi2w+cexwc4ehMsD4GX4
         mAROr/gtaziU6F8FYxu3sEOpm/l9NtAM1k5K+E1rG1dK1QOG10TIYBtY8U4Ggknbj6+d
         B+EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uDT7v5EgMDXpWmJZb7OIrcHi4ELxSVTwCk95a08JWc4=;
        b=DUih2xlEgKjRbxRgZaX/z3v79tptXoPVw/5mFhY9diSKPAKZN4kwQOmF4VLNW21G+2
         Sve8gQ5OgOY77QnnjVxY24V5h7sMRJfrZqVd1X3tAH49zSHxCbACtlVCGTorI7rPbz5/
         zKHwrsypUkMqnbaOzU/XkbtTBqkNKtLipphjfoh4m+Kq/D6m0i8POKTmmwCnE1znHHAz
         NeHjhpWfABABM9Csen6J4egKcW6oHet82mLV/YT86ZJVdHrfF6hZzo5ed5UAciT20u+s
         C//XRRHSzM1Moyth+FTYuf7Kiw3+VBAGDbliLc5YD4qEk/pz5LOxp+i41alxpXOD0tRL
         um4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533gMmANb2mZ8DQcQ9+OLfXMZj7aF1g/z9wQNK9rnam+f+q8TYnI
	DHnpF+p7vfsNHiYJSsiRhVY=
X-Google-Smtp-Source: ABdhPJweZLOPX4BHzGqn//y9NFv0/vvUmMi6vwYcySEcs8uIvv6Mb+y1KjFiTAocIwZLGxcyuyBiDg==
X-Received: by 2002:aca:6509:: with SMTP id m9mr1041498oim.35.1613001415336;
        Wed, 10 Feb 2021 15:56:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3407:: with SMTP id v7ls879088otb.9.gmail; Wed, 10 Feb
 2021 15:56:55 -0800 (PST)
X-Received: by 2002:a9d:7694:: with SMTP id j20mr4047387otl.89.1613001414951;
        Wed, 10 Feb 2021 15:56:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613001414; cv=none;
        d=google.com; s=arc-20160816;
        b=W3ugyOba2yXGi9ESVJP4y69sZhXjsVUP8zDLubbMrCF5yI6BuIqf/WK1rX8DqQvgZi
         tLojwi+IAjYap+sq6gprQIkmy4GhK4kSTDggbsFa83I1/qvjQbGBh7wfrROOb/LQpURn
         kIXE5DGlopIB88Ty+JpZYTsy5MYDOrIhrIHychCUlyOHBL4H2T83YiwXsxtQ0JdDbZHU
         vXsOumWVF2sorOjDJLca3qxTxF4LP0EP/KB15p8AydZ2+UD61z0ZzMO7UBPSOg/DvCF2
         JUHP/vlIZdK5+f49IyakcvdGMKH99+i87CtP3wh2HY2o0WBX8KvGmwQLd6hvnFeDF6xi
         ks8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NlBU/EA5O5TjlAdnlvz/LDwHm49DsW41/c60GtVRT74=;
        b=foIeD5o6j8Gzl9WLzxu20MhaLu7rCJPw5KbXmfb1dFs2OAG7vDblCJ6uWl38bXuaU/
         WEHtVNUNNrQVg524sUbfvQmmcPKetdax+rRAr1irlB/jsMof0K/nqNkvyECoFHfP6H7i
         JBkbRHRYNIh5aTgm7co5RnZHLC2drBDptnoOyFeVrHYaJpWLZ622Z3pmmK9VQNaCEmkR
         oj/Ei7OIf/mlKmwYqyLgHHDxCqzOO0hsRZrjiU/Pxkp3VsBKLHtoO4S2sxeHfDBO51Zo
         XU6ZG1hQXLHHQbaIecDSn+UPKEIrAYclOmGQYUOMnrT2S/SA0OBIxaxtt5S2tEnTZS1T
         rY9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=pJPqASHZ;
       spf=pass (google.com: domain of andrii.nakryiko@gmail.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=andrii.nakryiko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id g16si159864otn.3.2021.02.10.15.56.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Feb 2021 15:56:54 -0800 (PST)
Received-SPF: pass (google.com: domain of andrii.nakryiko@gmail.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id k4so3849839ybp.6
        for <kasan-dev@googlegroups.com>; Wed, 10 Feb 2021 15:56:54 -0800 (PST)
X-Received: by 2002:a25:9882:: with SMTP id l2mr7298911ybo.425.1613001414729;
 Wed, 10 Feb 2021 15:56:54 -0800 (PST)
MIME-Version: 1.0
References: <20210209112701.3341724-1-elver@google.com> <20210210055937.4c2gfs5utfeytoeg@kafai-mbp.dhcp.thefacebook.com>
In-Reply-To: <20210210055937.4c2gfs5utfeytoeg@kafai-mbp.dhcp.thefacebook.com>
From: Andrii Nakryiko <andrii.nakryiko@gmail.com>
Date: Wed, 10 Feb 2021 15:56:44 -0800
Message-ID: <CAEf4BzaO+cR3b-TKb6BBsj1_gmAbWuq1JriGU7C8qMuiHz-5Gg@mail.gmail.com>
Subject: Re: [PATCH] bpf_lru_list: Read double-checked variable once without lock
To: Martin KaFai Lau <kafai@fb.com>
Cc: Marco Elver <elver@google.com>, Alexei Starovoitov <ast@kernel.org>, 
	Daniel Borkmann <daniel@iogearbox.net>, Andrii Nakryiko <andrii@kernel.org>, 
	Song Liu <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, 
	john fastabend <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, 
	Networking <netdev@vger.kernel.org>, bpf <bpf@vger.kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	"Paul E . McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	syzbot+3536db46dfa58c573458@syzkaller.appspotmail.com, 
	syzbot+516acdb03d3e27d91bcd@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andrii.nakryiko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=pJPqASHZ;       spf=pass
 (google.com: domain of andrii.nakryiko@gmail.com designates
 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=andrii.nakryiko@gmail.com;
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

On Tue, Feb 9, 2021 at 10:00 PM Martin KaFai Lau <kafai@fb.com> wrote:
>
> On Tue, Feb 09, 2021 at 12:27:01PM +0100, Marco Elver wrote:
> > For double-checked locking in bpf_common_lru_push_free(), node->type is
> > read outside the critical section and then re-checked under the lock.
> > However, concurrent writes to node->type result in data races.
> >
> > For example, the following concurrent access was observed by KCSAN:
> >
> >   write to 0xffff88801521bc22 of 1 bytes by task 10038 on cpu 1:
> >    __bpf_lru_node_move_in        kernel/bpf/bpf_lru_list.c:91
> >    __local_list_flush            kernel/bpf/bpf_lru_list.c:298
> >    ...
> >   read to 0xffff88801521bc22 of 1 bytes by task 10043 on cpu 0:
> >    bpf_common_lru_push_free      kernel/bpf/bpf_lru_list.c:507
> >    bpf_lru_push_free             kernel/bpf/bpf_lru_list.c:555
> >    ...
> >
> > Fix the data races where node->type is read outside the critical section
> > (for double-checked locking) by marking the access with READ_ONCE() as
> > well as ensuring the variable is only accessed once.
> >
> > Reported-by: syzbot+3536db46dfa58c573458@syzkaller.appspotmail.com
> > Reported-by: syzbot+516acdb03d3e27d91bcd@syzkaller.appspotmail.com
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > Detailed reports:
> >       https://groups.google.com/g/syzkaller-upstream-moderation/c/PwsoQ7bfi8k/m/NH9Ni2WxAQAJ
> >       https://groups.google.com/g/syzkaller-upstream-moderation/c/-fXQO9ehxSM/m/RmQEcI2oAQAJ
> > ---
> >  kernel/bpf/bpf_lru_list.c | 7 ++++---
> >  1 file changed, 4 insertions(+), 3 deletions(-)
> >
> > diff --git a/kernel/bpf/bpf_lru_list.c b/kernel/bpf/bpf_lru_list.c
> > index 1b6b9349cb85..d99e89f113c4 100644
> > --- a/kernel/bpf/bpf_lru_list.c
> > +++ b/kernel/bpf/bpf_lru_list.c
> > @@ -502,13 +502,14 @@ struct bpf_lru_node *bpf_lru_pop_free(struct bpf_lru *lru, u32 hash)
> >  static void bpf_common_lru_push_free(struct bpf_lru *lru,
> >                                    struct bpf_lru_node *node)
> >  {
> > +     u8 node_type = READ_ONCE(node->type);
> >       unsigned long flags;
> >
> > -     if (WARN_ON_ONCE(node->type == BPF_LRU_LIST_T_FREE) ||
> > -         WARN_ON_ONCE(node->type == BPF_LRU_LOCAL_LIST_T_FREE))
> > +     if (WARN_ON_ONCE(node_type == BPF_LRU_LIST_T_FREE) ||
> > +         WARN_ON_ONCE(node_type == BPF_LRU_LOCAL_LIST_T_FREE))
> >               return;
> >
> > -     if (node->type == BPF_LRU_LOCAL_LIST_T_PENDING) {
> > +     if (node_type == BPF_LRU_LOCAL_LIST_T_PENDING) {
> I think this can be bpf-next.
>
> Acked-by: Martin KaFai Lau <kafai@fb.com>

Added Fixes: 3a08c2fd7634 ("bpf: LRU List") and applied to bpf-next, thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAEf4BzaO%2BcR3b-TKb6BBsj1_gmAbWuq1JriGU7C8qMuiHz-5Gg%40mail.gmail.com.
