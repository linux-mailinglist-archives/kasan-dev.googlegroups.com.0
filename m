Return-Path: <kasan-dev+bncBCMIZB7QWENRBT7Q5KBQMGQEIIWTSZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 07180362F38
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Apr 2021 12:28:33 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id i12-20020a0cf38c0000b02901a283706bc1sf3000626qvk.2
        for <lists+kasan-dev@lfdr.de>; Sat, 17 Apr 2021 03:28:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618655312; cv=pass;
        d=google.com; s=arc-20160816;
        b=JhGL9pSY23CzAJ1rkW+wekoSeIoj26InOthvNxe+XcGjW3UchlkHtojAYhj2ArC8E0
         rdfEY/uCAtqlg0ZEIcu50nTVrlgjgp/Q7AkUjJZONUjCDThqqlcKqP0L96GIYIY6Bfr3
         KBB71ycVDnqRROy6ltKpOH/7NipTM68pBJDNhba0pdbjRPblM+B0uemrmlmk2zUkN29t
         Nx3OCT1qWudZj14dTn+qxo9i3/3TCPcAjxcP20u2iXBWN5XT4RbSuDDIOjLKzF6/9Yl4
         T2CA/5hE4IcWxvtJntP7mLDlqtL4R63iXAi0U11VX0Uq6dPY5vOvSQFaClEzxc2VvuKP
         G46Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fwTy2Rzvu7g7zk4EUA8DDdyalfkMrUQdLr0sTOUEYKM=;
        b=RzSvZFJ/rY0jhssf2itPsNBTXksxMhMvxMTa1qXTd76gHco1XRansQwCcn6SLtAl6W
         pW6b465j1u8+sZo2y6DFz3HUjuoox2qyseBqNGTmCpyVQTh/osgN7qAkAAicim0FAZ09
         onzZe+zRhchFZ7FC1+NY+ezRZeIn2ZrjCG/jcr3CI9xbReN0nLR+IV0gsebiJ2EP18Jx
         TE8yk/bC3il+UsuKRCY7W7JpnBDaam+EkWsfX00rlekdtpKS9RQUa2nO29NKWWuOQ2cy
         vVjw8b9q+yJG20WwlccyobG8niPCpYz/XTGPNO5HBNYraFjniVhW22oACN+2ZW872rYB
         vPCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kYcqBFfK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fwTy2Rzvu7g7zk4EUA8DDdyalfkMrUQdLr0sTOUEYKM=;
        b=QvFf1boJsUvNmtVHoszEa185RAM3wYWVUOijTqXtGhKlMMyEhkg7gh5THASsNLyJ/s
         iegnL926lZots5ERNbYpleQDoDcpyzuGQsCiQgOzvgXLuKOQ1p9cwvaTwRCjeZTKVnxZ
         r02UOjrkFRRUCgHn/FndY+q7SCcOoYXlHNjA3Y1zQmqSXwpfbKrNnwgEfLGg9MyBPNPc
         GkT98C9zPLsI3cDS7TN9Z+uZqmoep/lJ7uXHMwAeIweSM56PtA45YpmEGVtA5lHcrwuY
         gZxMrQn+Q+ijLkZeya5gXn0aw0W7Ni2ki1IEbAyHvZJ60Qs8jI2YxBYqlUF2GOWt9mNI
         qOLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fwTy2Rzvu7g7zk4EUA8DDdyalfkMrUQdLr0sTOUEYKM=;
        b=lWYhAmetpuVYQtoeLHoxTA0Lr/Qog4zgdFOcIa9MqH9DNl9PmF1HfPE+7qsgXSFiT5
         A9x2ciX7AlJFvp7SvSgWvGsrPkCB9CVntYE+o+n9RAWtnoHX9cQ/oCZt85Yc2CDFlgLn
         agiOdq6J+yNRv6Rw+D8oD9loQEpEHDcf30b1GLYmHdghHHzM7gEE8uFCsC4rbceVl3Zs
         gkpfXf565KMro5q1xLhPFmC+N+rQMXApLExbd6dOgu/awdDGuwBK0w+4ypH9H1qfEW+z
         xcVNeYiERuDum9mUbMgDdL+TbClWx8nE8GWu+H3kK5uarsdGKkjBTF8bIBhaNTnvAD/o
         lyrA==
X-Gm-Message-State: AOAM533mxdzMT8yXU/0WbAU5QA1bHnliPrV5qjRbkoWq6u9nGN1Xd9Yt
	mbLLsPvpymSq5hgG52VJL70=
X-Google-Smtp-Source: ABdhPJymwRoUokUOpXkJzU4nUOkfR7si0U0yicpuLPWINbrQINd4voZTo/1NfJUpJCLI3DZORN8sNQ==
X-Received: by 2002:ad4:522b:: with SMTP id r11mr12797888qvq.6.1618655312005;
        Sat, 17 Apr 2021 03:28:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:28c8:: with SMTP id l8ls6521543qkp.2.gmail; Sat, 17
 Apr 2021 03:28:31 -0700 (PDT)
X-Received: by 2002:a37:65c1:: with SMTP id z184mr3304591qkb.431.1618655311599;
        Sat, 17 Apr 2021 03:28:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618655311; cv=none;
        d=google.com; s=arc-20160816;
        b=H0q9AMVWM6Xc/lQ17Z3JINxqlJpOivS1+/AlZ304okZeaJVs6c1YMbPNjNwd6fOYLC
         9E93BG9KVl43HNUfBtTLCcRO2buEqkUhtubArUgYT6Xh2iGJOcKj4XEJuwoCBYvVlb/e
         lH7A+x+U34gxVngxgXXmQLw2O15Iv/r3qldnUIAa4F+CUeALE8IWdMmZ0ndmzjBVjPTx
         tv2wavVjrOC+QBpvE78fQz68PsoRIo31tAg0RzKqHC6t+XE0LRkOlCfvmRhAnnj4Q+Mi
         y2bQhP7JmZ5WX6F+4HvYzheOwEdnrpkmHu8SIb3K3K0DdpQbV9zJCFgab2j6D28nniag
         M/2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Whd9O2gSic3eS9cVfE6rnRrtSx2z1faJ3q+diFSdkJE=;
        b=Nw9JjD5XnWJW9O7/3dYxDF4SA3uMYdIecDK9iU92Gtwe3TEWNcuuFb7HbL8KUVJH12
         88yqrA6cVBjz8CQXqPnjjJnL5R3J5tZ+iMJO84tbdZxWLSUQCRnoggwcjEKm07j55+Kp
         LmXOOzwA/xfZJRC6m8keOlgOTWNOb3PEBFBUJXDAisAIdcKQVHMJW89g3wkMUdA4yxUC
         odzsId/DRZTDGv7dsSEfhoN/dJjz81FjgQR7VpUwVsOxqLzFBgvF/LyaMo5MlQc2YGs9
         pnRjF64VVvd0H3ky2wtq4ET2SxBS/+DdIPOzMwGoGWtpp4MlG2h1vNsptBerPyBABp5q
         fJFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kYcqBFfK;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x736.google.com (mail-qk1-x736.google.com. [2607:f8b0:4864:20::736])
        by gmr-mx.google.com with ESMTPS id 22si626872qkb.5.2021.04.17.03.28.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 17 Apr 2021 03:28:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736 as permitted sender) client-ip=2607:f8b0:4864:20::736;
Received: by mail-qk1-x736.google.com with SMTP id x11so31380665qkp.11
        for <kasan-dev@googlegroups.com>; Sat, 17 Apr 2021 03:28:31 -0700 (PDT)
X-Received: by 2002:a37:a854:: with SMTP id r81mr2245601qke.350.1618655311147;
 Sat, 17 Apr 2021 03:28:31 -0700 (PDT)
MIME-Version: 1.0
References: <0faf889d-ac2d-413f-826e-6c2f5bf5aaf2n@googlegroups.com>
In-Reply-To: <0faf889d-ac2d-413f-826e-6c2f5bf5aaf2n@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 17 Apr 2021 12:28:19 +0200
Message-ID: <CACT4Y+ZHyat_KE+yQ5z7xpF+RfW39tbpYS6t=9A82dvbZcuuKQ@mail.gmail.com>
Subject: Re: Regarding using the KASAN for other OS Kernel testing other that LInux
To: Tareq Nazir <tareq97@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kYcqBFfK;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::736
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

On Fri, Apr 16, 2021 at 9:50 PM Tareq Nazir <tareq97@gmail.com> wrote:
>
> Hi,
>
> Would like to know if I can use KASAN to find bugs of other open source Real time operating systems other than linux kernels.

Hi Tareq,

The Linux KASAN itself is part of the Linux kernel codebase and is
highly integrated into the code base, it's not separate and something
directly reusable. Think of, say, Linux TCP/IP stack implementation.
However, the idea, algorithm and compiler instrumentation is perfectly
reusable and KASAN is ported to several BSDs and Fuchsia kernels at
least.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZHyat_KE%2ByQ5z7xpF%2BRfW39tbpYS6t%3D9A82dvbZcuuKQ%40mail.gmail.com.
