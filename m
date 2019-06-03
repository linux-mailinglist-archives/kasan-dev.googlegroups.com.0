Return-Path: <kasan-dev+bncBCMIZB7QWENRBTOO2TTQKGQE4UQOLLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A50733194
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Jun 2019 15:57:34 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 126sf14401997ybw.9
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jun 2019 06:57:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559570253; cv=pass;
        d=google.com; s=arc-20160816;
        b=rF54W4MUN18YJ8DdMT5nqu8wEy2kqStt7GmRe/GXIwU/uIlbvModcuO7tQwdg7cVvh
         qgJyqkK9cCMdR40nNoMUhh2liuOlRI/HI1CYwtny1UQ8aM5MTBt1nWyUohbwTGTmp/fh
         HdGlA49bwG4zSDROmnMHFQ2XvQWGBQTGHiq0VtOo23Jo1N3RvG4oGfRtgSjBTRuXlwF0
         hGUIIgNbGvxBjCUUAntONRid0xn7SRCG/8kWi4iwgCvYqzQmK+Dnu7vH8+uaMbhtzRWO
         o/Fy4hEQ4Sa3xBP15K4VLzdo+bn/DowSi+D9kfdRjdvJgCp2TQ1pKGYxYhbO1PACt3vm
         HuBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6s6F+7vs4TW5g1FYfFKphRYxpbUgX3SKN3ajaWxwQ8U=;
        b=Cq7EQQ/CNSKg3312gaTeW8d7lJQ6dyxrGiRFsDJuItAlpBmNsHsbw5SG2XXWNtbuSj
         uA1ErrlzVUC5esSIS0GIQt4XR8I8hsiF5lYnSFcFphiZrfaUCddZz+QU6Xk2nTSRPMiD
         TB5nAyXIPAALHv1ll5ToflmoAA8yz5LOrdK6fd3BJw58m0L3j3xScXgBQqarDqsWwpHi
         0hkxSeP2njfe4tiAvnFbIkT+Vl+UALAlpDAbMV0U5ZlNq/j4HzBKNL58p2V4u6km/gdY
         2McLTnmhHun+eEiUJxSjRRxJkKFc1mHsFj0b4q/eXCtN91WQz4hNGrPMIYCUGgimQ70+
         5JaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LhPu8xWz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6s6F+7vs4TW5g1FYfFKphRYxpbUgX3SKN3ajaWxwQ8U=;
        b=sGJliCYILHbfyDXlXj9zG2k8iOOEhndxxsqD9OXMFKMDVIz2oRRyQoUHq6i5VMF+Rw
         BRKIcXQQmYvZpdA+6woiOgzvmjis9bXTHjlrleD6059INs3OIOVMZe5l/sJyhfA2QomZ
         hz5lbZF+/Ry3gr1Zz6EOj0ZHuRrCPtrjsLHroIxsClzpU60FDMp7DwMmvkbo842+F5ip
         A/5RQY7FMPuAFHjP/qvdPnqA7Zh42zfKlN+R0T+wjmUCop4J1xnT7nXavw42XdIvoa6b
         frWOl7iwLupZ3vu8cqVkXAkGbLY/hSHq80MHs+mj+zN1YvhXxFIMxkPsjnTDznJzMrvi
         OXuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6s6F+7vs4TW5g1FYfFKphRYxpbUgX3SKN3ajaWxwQ8U=;
        b=KIgA21WoUDBSDEjLXGCpDPV6UosT5vDSRl4Gs5ZQY5in17JqqleNUdbx8mAUKth3wQ
         c7tCWoKd7lzU/Ru8Siv4MaYj7Jdp8qt7jrMhVmYqXFcpfUXMmp07RPd+Jb2oIoZzrQuq
         dG2k/CO6XIC2e7PwMvw8cdI8wzOb9lKMou0Bb3iI6EPYfWkjZLe/oOLdf19P/lpLz+9R
         qW3NvHi1yJ9vmGfzy5bZUo4mGsWPocQNNWhv/taH+EXBgxcHVGFbxUIXmtF3d/XnF12P
         sDdiQhqj77fx2inzP0WD8E3JYKEizuW0X5AY56G3fL/mVlZ6JmUos2u+58Zjt5DsTfQk
         Cl5A==
X-Gm-Message-State: APjAAAXkavL5kpAfpBi9/fdUFlMTxa8mPkE5AfWeVdXrDnuLwZmjqE3Y
	eNb6gitdprn0NEuAQMy6aTU=
X-Google-Smtp-Source: APXvYqxad1kdlQ++ogCLXN7HwWpzHPd/SBACThv/lJXGC4Otm1zYY20ZAeW/e92iZ92gKL4TjxuoZw==
X-Received: by 2002:a25:26c5:: with SMTP id m188mr13058664ybm.16.1559570253235;
        Mon, 03 Jun 2019 06:57:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:7a92:: with SMTP id v140ls1997833ywc.5.gmail; Mon, 03
 Jun 2019 06:57:33 -0700 (PDT)
X-Received: by 2002:a81:a042:: with SMTP id x63mr5260355ywg.396.1559570252987;
        Mon, 03 Jun 2019 06:57:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559570252; cv=none;
        d=google.com; s=arc-20160816;
        b=jxIcnxIUuYD9iAdqWnp7D2uVaIfE0sM73kaPeSQ6yJjF2A6gdEBhW2PWo//T3bCcqn
         N3DGnQNigLWykmTC6mRg9VsctTxFE+GefcwKSTzrCq2hTzYoMuyAUUcYbX37F9y2n+2G
         0zPDFGOzCcnmxMJx7kbF5YrdI49X3QgBVhYsR96FYgZx2ClpKT5WgVXR4iZieXQGV5N/
         K4EbfvQIaK7fOOvhNmVkQTKFUj21Ud2hfEo+ia7DpgCzMx84zzyV6OAs/zEcuwIODVVn
         y81K6fpiOj646+Mb973OJdfnOUWVBS104ywh6jrA++RsfkkvhvniUatPh76UcxeGeQYg
         W2zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZG5uXc5vVJWTTjlBGkapuRw2p3D6SHPt1wiCMppTPLI=;
        b=JzvlRM0G0dILRLg44YV1q0wNZKLUQGQdccdxHmXI1RL9wBM5oH4a1EkPp3lWB9Sm7s
         1x7QihERvNOVAIzZWVR7U03ftxUgkv02N7MEHKpwhpkg8i8oBEGSlTwKDjhmiv+NPQuf
         C+LIMdrX4A44AC65o5HUwF36U3DLhFlQ9nKJHAu14gto0EL0lJGmE5jxaGhmCz/coAjD
         N7MMrEJD0yCV4lGMVzUitZ6Kvfel9Cvmo3UhpRqVTCUhXDZ/uVaLcd1nMUUOhMTRhE6Q
         0Iz3wRvQCbXK5JVsx65B/MRFQkTSEm9VuYzUV/tUfb5bHO7NLFlMfyQlVYImuW/YbEcH
         CZiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LhPu8xWz;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2a.google.com (mail-io1-xd2a.google.com. [2607:f8b0:4864:20::d2a])
        by gmr-mx.google.com with ESMTPS id d74si536531ybh.2.2019.06.03.06.57.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 03 Jun 2019 06:57:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) client-ip=2607:f8b0:4864:20::d2a;
Received: by mail-io1-xd2a.google.com with SMTP id k20so14324480ios.10
        for <kasan-dev@googlegroups.com>; Mon, 03 Jun 2019 06:57:32 -0700 (PDT)
X-Received: by 2002:a6b:8d92:: with SMTP id p140mr15896861iod.144.1559570252416;
 Mon, 03 Jun 2019 06:57:32 -0700 (PDT)
MIME-Version: 1.0
References: <07a7e3d0-e520-4660-887e-c7662354fadf@googlegroups.com>
In-Reply-To: <07a7e3d0-e520-4660-887e-c7662354fadf@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 3 Jun 2019 15:57:21 +0200
Message-ID: <CACT4Y+aanRYNL6N0M7QxftmBcLQi44MenZ+oOUap8g9AtvzZvA@mail.gmail.com>
Subject: Re: Kasan for user-mode linux
To: Marek Majkowski <majek04@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LhPu8xWz;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d2a
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

On Mon, Jun 3, 2019 at 3:54 PM <majek04@gmail.com> wrote:
>
> Hi,
>
> Is there KASAN for user-mode linux?
>
> Alternatively, is would setting CFLAGS="-fsanitize=address" make any sense?

Hi Marek,

KASAN is not ported to UML as far as I know. -fsanitize=address needs
to be passed to compiler for KASAN, but that's not enough because
there must be the runtime part too.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaanRYNL6N0M7QxftmBcLQi44MenZ%2BoOUap8g9AtvzZvA%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
