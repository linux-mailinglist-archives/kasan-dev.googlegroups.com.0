Return-Path: <kasan-dev+bncBCW677UNRICRBQGUUTWQKGQE4ZURQGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D32EDBB87
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2019 04:58:10 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id t65sf3437586pfd.14
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 19:58:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571367488; cv=pass;
        d=google.com; s=arc-20160816;
        b=KnkyvoWTkOYrKGc47x6BIkfiyi4Iqi+fQkHhK01mJanR0c1bL6xDjSqabVW6jN14I8
         9YzzfLmJ3tEeMncPUQr5ojmSRL+1axfiuI7QxyBM0fGKYXiCkgluyTwbq5qEe/x4mIeD
         vtiqhwS4bHlNp84KN+YxbjmSk+Dbb8M4QBeLkrnTtf9sJWKsPX0AYc6RE8+t6JamfALn
         2AkYefW/NFg9wx3R0fTzqTEooZak/bNSJoM7lnlVkPuJTcDEcoUENrt6sr/IGXiRQ3j1
         MUL8SY60OmbAutX4AnBYGL5O+9Ghys8sccgR/yOzaPNoWI14nWzXNOw+zba1WWtSsBZy
         XtmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tG77qL8vnk6YR9UfzIoFqBdlH1omWMC0MOWor4w6Wm0=;
        b=J9MELZa2saoHUIyb0nzE4LlYs9xIHdyo5uyYponzjYLLHdC5L5GQ8U/QpgXLh/VQhq
         iQcYFwHgnQqAI4F77JQUfh1fnR+J2jNMxY9ALoCpBqHGLOx8BOtpKLrw/bsa2G6IQIuf
         HhTyp9953rBvKewCN5luXaAc9Q0kNSu6/m3EDuUzhe7PXma2MfygDrDZA/f4Uou37pd9
         N2LJhHnpfVm6+dlvfn9IVR084NXTfovmq85G5cgAERYw2l1Rwa/qcsrU87/yxNeLUFx5
         hClgfrwkP9Xl/DW54k9oVKAPehqBrcHj3zgDTd9LqwgzkuYcPFb30uYw07FOkoTRl9aV
         aZuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=dU09HL7Y;
       spf=pass (google.com: domain of paul.walmsley@sifive.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=paul.walmsley@sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tG77qL8vnk6YR9UfzIoFqBdlH1omWMC0MOWor4w6Wm0=;
        b=aJDMcECPJOfqAiGcsMN0/5XK+7ca5uY/TKnPlFeJ/lpkyPyVJslFY13R8ndD/VDz/F
         qct4AC/eufUqGe+zHpTyLTmuInRnqQvGnGyaVjP5BbDjnR0iEPWWMWbdjqOw2ilkllG6
         SmLO2+Rq8IOT3KeJo9IUcR6ye6BJ9m+LK1AlUc+CKW71O/RqzEnjHmNSMuROirdfbt/r
         xvHrf4Z4+2hFLAiJEWLI8+m1Dq3uUClXEkkeku8FSdG4jR56prx9Wtt0FmfpxL92XkIr
         LAtBdir17NLaoOEKL50hK9F/yphsv18mFtDpNz860C20jX4/b9TytDdoQ/rUoOzNZlUL
         QjTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tG77qL8vnk6YR9UfzIoFqBdlH1omWMC0MOWor4w6Wm0=;
        b=JxlHIdPWkbPMMV5wO1BOOQwFkEympNrHfU/y5aR4PuR9+6UzPvCu5ZW5HUNR3jSx+a
         03jl+D3xJVOlAHjNCYodSKquo5LMlnzxa6CpNBZUKM7wRwU1jwfWKIizY4oB4j9t5Ldn
         wEWXF8mmYD6XvuHyAk4q8gD0jdfqKCnqq+PiRhn3mRlZq2Ci+i7QigwOU7AOn7x2+d1S
         Z5g66lOZAuR39uRsic0zukHyv6/iUA/OAv5uUUrZ9FbIpJa7+fqpRFafXUCuwq3IB8bn
         Z4yX/6xOr4/Pp66lH1H3DMCbijmSsED0FMGwxAIDIJC/nGtdbJioQsBltZztjdHJrwgu
         gzqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXcbP1AJliwCv8ZG6pHd6JXW32Nd3OsHwmnA0MTBUzY6i/fsfML
	Chmt/C2TGKs/3Ur7LY5VQSY=
X-Google-Smtp-Source: APXvYqzAM9cbXDnoFtmzyUcoZ2/z2cmDpwUa4xcQxKRm62C/Eog1acM6gLmJLXkJMPYzxIaav+/08Q==
X-Received: by 2002:a17:902:930b:: with SMTP id bc11mr7404423plb.284.1571367488494;
        Thu, 17 Oct 2019 19:58:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a589:: with SMTP id az9ls1409143plb.12.gmail; Thu,
 17 Oct 2019 19:58:08 -0700 (PDT)
X-Received: by 2002:a17:90a:a00c:: with SMTP id q12mr8310471pjp.102.1571367488177;
        Thu, 17 Oct 2019 19:58:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571367488; cv=none;
        d=google.com; s=arc-20160816;
        b=UCuwimEP9ZwUkdUWpQBMxGDC8yd/B14vBTNIOmnoBCi4bB/c62g5uK/RAS9BhF2Pha
         vi4hoaxOr3ojPDdX5e3/geqF1mIeQT1pKYac/C0eUhXQYYTjELgZZPFc41QzQRDJcj5L
         D9APKjKBNI+XjWshyz4o+Zg0J0eANefuxtAb/qXj2ICxqnIAlnRoWK12NppbeFjVQh/0
         ttqn0/1jZKNlv4sdB6yQ8gZDqxhp3R4m4FbqIv/wfZaNLA0u4rWYSZp0onvGLgf5JC5v
         pwE63quURwgZtkpQp7HEzcYZll3BYDzx45znLTi/ZDkxe4UnZ0OhcaAWy8sk//zGOSsV
         ZiGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=6vl776tt39Djj97+yEKzgcDA8S7SdrfVeVZOrfDrtPA=;
        b=VWKcUpcxZM4429xP74Oz01EU6KpfzxCoDuAbw2PzKKy0CJrrzT6P0+vzNRHVh7MkOq
         e5RJ0kDyWZqZnv598hLy/PhGEZ8lbazm55sHXrvbqCAv6+EQ9uzFI7XAbJm0/Bm4gGIm
         usH2QKzqggcZ1qaZJai6HXRiYJLOr31QseEgfP/+GYn+1v+jsDAUkpYzF6ywSINOcdHH
         trqFwS7rXdQdtaH7G9QCyCOUHsYfIUuInsZ8xN2dze+3N4n69/pIpnOI9Wo7L8oKu/Jj
         o1e2cE8DdHYcOpJ6x9XasSK2ddZw6+ZQEGa+Yt+bYd6JKBsX8fbsNjnPg+k250lVatlv
         yV4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=dU09HL7Y;
       spf=pass (google.com: domain of paul.walmsley@sifive.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=paul.walmsley@sifive.com
Received: from mail-io1-xd42.google.com (mail-io1-xd42.google.com. [2607:f8b0:4864:20::d42])
        by gmr-mx.google.com with ESMTPS id d3si206465plr.4.2019.10.17.19.58.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Oct 2019 19:58:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of paul.walmsley@sifive.com designates 2607:f8b0:4864:20::d42 as permitted sender) client-ip=2607:f8b0:4864:20::d42;
Received: by mail-io1-xd42.google.com with SMTP id r15so1963405iod.9
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2019 19:58:08 -0700 (PDT)
X-Received: by 2002:a05:6602:1c4:: with SMTP id w4mr6000255iot.153.1571367487601;
        Thu, 17 Oct 2019 19:58:07 -0700 (PDT)
Received: from localhost ([64.62.168.194])
        by smtp.gmail.com with ESMTPSA id o66sm2100434ili.45.2019.10.17.19.58.06
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Oct 2019 19:58:06 -0700 (PDT)
Date: Thu, 17 Oct 2019 19:58:04 -0700 (PDT)
From: Paul Walmsley <paul.walmsley@sifive.com>
X-X-Sender: paulw@viisi.sifive.com
To: Nick Hu <nickhu@andestech.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>
cc: alankao@andestech.com, palmer@sifive.com, aou@eecs.berkeley.edu, 
    glider@google.com, dvyukov@google.com, corbet@lwn.net, 
    alexios.zavras@intel.com, allison@lohutok.net, Anup.Patel@wdc.com, 
    tglx@linutronix.de, gregkh@linuxfoundation.org, atish.patra@wdc.com, 
    kstewart@linuxfoundation.org, linux-doc@vger.kernel.org, 
    linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
    kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: Re: [PATCH v3 1/3] kasan: Archs don't check memmove if not support
 it.
In-Reply-To: <ba456776-a77f-5306-60ef-c19a4a8b3119@virtuozzo.com>
Message-ID: <alpine.DEB.2.21.9999.1910171957310.3156@viisi.sifive.com>
References: <cover.1570514544.git.nickhu@andestech.com> <c9fa9eb25a5c0b1f733494dfd439f056c6e938fd.1570514544.git.nickhu@andestech.com> <ba456776-a77f-5306-60ef-c19a4a8b3119@virtuozzo.com>
User-Agent: Alpine 2.21.9999 (DEB 301 2018-08-15)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: paul.walmsley@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=dU09HL7Y;       spf=pass
 (google.com: domain of paul.walmsley@sifive.com designates
 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=paul.walmsley@sifive.com
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

On Thu, 17 Oct 2019, Andrey Ryabinin wrote:

> On 10/8/19 9:11 AM, Nick Hu wrote:
> > Skip the memmove checking for those archs who don't support it.
>  
> The patch is fine but the changelog sounds misleading. We don't skip memmove checking.
> If arch don't have memmove than the C implementation from lib/string.c used.
> It's instrumented by compiler so it's checked and we simply don't need that KASAN's memmove with
> manual checks.

Thanks Andrey.  Nick, could you please update the patch description?

- Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.DEB.2.21.9999.1910171957310.3156%40viisi.sifive.com.
