Return-Path: <kasan-dev+bncBCMIZB7QWENRBKNHUH4AKGQE4HCWSSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id EC22621B42C
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 13:40:26 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id gp8sf3937712pjb.9
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 04:40:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594381225; cv=pass;
        d=google.com; s=arc-20160816;
        b=GcfX3v9z4hUg0e3NK3zN5MT2t5OeKhtLsvDn3LEA3dMWk82JCeYFxRy64MA+ExfQ70
         XbTjwm64RxGtWjIW+W4hWL7MynZz2WMJmxctFctIyc9cgx9u8cvP/4yTV1B8fC+l17ey
         i1huJ4V+l/JyS74TAiJmTfL1+pBr4bzfvENewqJo7AsAXYO6ufzHEjy61UlFP7QD7w8W
         ezQTVm3i2W6/MzLJIhBbC3LK651mDRwJQR7/dHn3XjPrgxIuxNtxymFWMdlK/JVgAbWX
         Ww5l+6bf44SEovwyl+6rr6MwJhwo4rOKUAlGRKmovv7DoMocRlyf2rrB2pEMwZzVRwmO
         whWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=J3ueDAXHhFxh4nDxXlwjmqHGte90Q+9qtpb3y+urBnc=;
        b=zd2bP9bJuBtrSyHnH69HYJkHMCm7T31ELtQB912CkYDJ+7FGE/fm6X6wNJkwVqyB1h
         BlwwA252k+iB5UBo6ooKGla3NhGHHdp/D4MYFPn7NINRCBFZSMXJYvyFCnqJMG36R/sQ
         7hzHodgnDouYllauNmzqhwLzT+vSWfBgLmXqjbU6NWfJKJQn9E1baftXbyIWWC9zDnWm
         RWCZWg87vXeqL21j0+NilG8GROyZkdWPKQoDGtVNTGEZMK2SvFs9VvrPoTdBibebR8Xq
         2PdFBBOTR4ZU5IOPuN1Tb2mJ2gu8lfCJuHrViHwZNa5n+hlJvredgUWyMSovh3eJxhnR
         ZOhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Fd4Z3DPW;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J3ueDAXHhFxh4nDxXlwjmqHGte90Q+9qtpb3y+urBnc=;
        b=YucoEdyh1e0rxD0bzkzC4yHmdMCyViYdmIsOuYF/lzoWNhHm2hxL6XWZ9chAM3vBRd
         lv04Zj04XF4QjWxt0MhdTx/deAR3X/0FmYvwjLqJngJeTHS5RnuAxLLFnHu7RNA1R7mm
         a2k2z06tIi+Sm+2Uivn0KnqfYZtWYjFdCtOIKf8xplmcYLx9FtJkOWC3/I7ours1X2N/
         8G0cQ3zPgtaMQx3fM7IfGMI952h01Ct7imVWQMcTu280SXNLxHE8FQzggnZ2Bk8O6wJG
         Am3r6BwAbdWMDTZMNWsA88Q1r3UMm2GrIII7NwrAI7q9LwcAqrWFY0mdBapYLfbRuzEy
         ixzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J3ueDAXHhFxh4nDxXlwjmqHGte90Q+9qtpb3y+urBnc=;
        b=gp9n07Bc9D6LvmJqSw06NNG7Bxim/vsc880zjUZDaEmTWSq94w/aagvfz+sqIKjZ3b
         HVeMtD4fyBPyGVOsHQlMzPN6ZhDwb2R7n9VwPfDACdoaOb/8/Ot9mulX6ekAeuNiVI4r
         WhlZihUMwNQJ46ALkqj7lZbvKh3xAXmeZgAXxlWuI/DEG1K4+UOLGomFqkliKAx3+aqH
         3XOilx0C3UUadyXJwZ3R+aCJilqABzWAHBYNaHtRbVdlMcGho31ScEkRGib+0tVRgwGS
         +nMCaxDxEQ5Qy5MV8BdXQtlCUvzXX6TMqCaGQFPgAMgLQ3Vtt46c/+pBa53/+b67rc4s
         uiFA==
X-Gm-Message-State: AOAM532JIJ7tJMUryq29qdWa7bxArFq9fnN0MS6HlrpSh7LgTTDFdYFs
	IgnxEbV7/zlbXCMHhLe5QmI=
X-Google-Smtp-Source: ABdhPJwW/hR7Qrukx2B++7qp+bOMMRUwgzdmZgIkhJpO/xRzSwg+zQfjUMLJ6+X8RSSBide9ll8cPA==
X-Received: by 2002:a63:9212:: with SMTP id o18mr40408894pgd.347.1594381225145;
        Fri, 10 Jul 2020 04:40:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:46cd:: with SMTP id n13ls2715325pgr.2.gmail; Fri, 10 Jul
 2020 04:40:24 -0700 (PDT)
X-Received: by 2002:aa7:82c8:: with SMTP id f8mr66223866pfn.165.1594381224719;
        Fri, 10 Jul 2020 04:40:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594381224; cv=none;
        d=google.com; s=arc-20160816;
        b=AEtEo6Ee0nrKxHPBDOelde06ZbzVuVSRVKYiucJHI87w6gIz6n6ipDLeXRzlgEh8nc
         0kX+zsnOTotBqvcFTR3Htsk45/GJlDPqBIOkAVhEYYc8D+q9dHLUkOru/yV7TrqWtGHc
         R+/EUX50+LhrKl/IkEJElVXGz5vLaw2zuCOn0NaRAw3u8d0Jq6nwvL3qkXhPQJZV1dEt
         38+67eymZrWdsQwzbWWn8mpb6sSU48FUSrYLh1oI6xRWpgKGADXDUo2encjbA/ezgAST
         bgBW+TvtDyF+VFlAHfKs4UZw/emRLNvvxxmrKYYAh8R/68ZriSBg6+xBXO+1JsWxs8dz
         89QA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Nga1GQSxZ+eCrJHxU313S5HSIYjd1WEaR6mKXxvpAiA=;
        b=DhnELJ+3INMF2QNzGkH75gvrjcAYSPKZqqVn7ilKsq/d3UfznhrgcT4I0w3i9s+kRB
         2WtkoplGhx43ncA3aDbTSnYRKFrn7R1p5HipCervk4JNFqTC+TRQ4pYQS8FedtFzarXp
         3Z2XRKDm2RoylBdW629FafjrA4oxxDUVFFGsBVDiOmIFoNwmkRHkWIq1lBk5tTyNlMdh
         lzymrJdh+ukKDyeqnc6ErXNBeMhxhJHxirHm1gY9qP67RKKrqzViK+RAczy/kqwJit3F
         7J6UPELUwTqmDMOYVK31YqTbRk8fKQdcOalWMNyKx4xvy/KSjcz6SNH2pgT2RkdeIxm1
         PO9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Fd4Z3DPW;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x835.google.com (mail-qt1-x835.google.com. [2607:f8b0:4864:20::835])
        by gmr-mx.google.com with ESMTPS id n68si355172pgn.1.2020.07.10.04.40.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Jul 2020 04:40:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) client-ip=2607:f8b0:4864:20::835;
Received: by mail-qt1-x835.google.com with SMTP id w27so4080886qtb.7
        for <kasan-dev@googlegroups.com>; Fri, 10 Jul 2020 04:40:24 -0700 (PDT)
X-Received: by 2002:ac8:41c7:: with SMTP id o7mr69778722qtm.257.1594381224045;
 Fri, 10 Jul 2020 04:40:24 -0700 (PDT)
MIME-Version: 1.0
References: <fb85b206-1d2b-4121-8ce5-f538eb21d8a4o@googlegroups.com>
 <CACT4Y+YtuwN78Eo8SE8Y4gLrBbLPOmoUDdcNTVcQ00DjM-dxLw@mail.gmail.com> <6b8d7eab-1c2d-4267-b2f2-34c4328f9953o@googlegroups.com>
In-Reply-To: <6b8d7eab-1c2d-4267-b2f2-34c4328f9953o@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Jul 2020 13:40:12 +0200
Message-ID: <CACT4Y+aqj1=8S8uM=XdxDkk8qKU9ofTEP4+4-D0W_kQokLGsCQ@mail.gmail.com>
Subject: Re: Is there a way to have coverage for "init" directory
To: Mostafa Chamanara <m.chamanara@gmail.com>
Cc: syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Fd4Z3DPW;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835
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

On Fri, Jul 10, 2020 at 1:26 PM <m.chamanara@gmail.com> wrote:
>
> Hi Dmitry,
>
> Thanks for your quick reply , I went through that link and this one https://patchwork.kernel.org/patch/11218151/ , I assume I need to use kcov_remote_start()/kcov_remote_stop() at the beginning and the end of start_kernel function (init/main.c).

I don't think this will work, when userspace starts, the kernel
bootstrap has already finished.
Do you want to fuzz it? Or just get a trace?

> If it's the right way to cover init process using syzkaller I have two questions:
>
>               1. kcov_remote_start_common(u64 id ) uses and id to get a remote handle, which Id should I use (I assume 0)
>
>              2.How can I give this handle to syzkaller so that it can collect the information and show it in the report?
>
> and if it's not please give me a hint to do it right.
>
>
> Thanks,
>
> On Friday, July 10, 2020 at 10:21:25 AM UTC+2, Dmitry Vyukov wrote:
>>
>> On Fri, Jul 10, 2020 at 9:57 AM Mostafa Chamanara <m.cha...@gmail.com> wrote:
>> >
>> > Hi all,
>> >
>> > I have been running syzkaller (with all syscalls enabled ) for several days and bellow is the coverage result :
>> >
>> >
>> > as you can see there is no coverage for "init", I wanted to know how I can have some coverage in this directory and how to improve it , of course if it's possible.
>> >
>> > Thanks,
>>
>> Hi Mostafa,
>>
>> Amusingly this was just asked less than a day ago, see:
>> https://groups.google.com/d/msg/syzkaller/nu2rHzA-Rs8/FuAyWRJiAwAJ
>
> --
> You received this message because you are subscribed to the Google Groups "syzkaller" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller/6b8d7eab-1c2d-4267-b2f2-34c4328f9953o%40googlegroups.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Baqj1%3D8S8uM%3DXdxDkk8qKU9ofTEP4%2B4-D0W_kQokLGsCQ%40mail.gmail.com.
