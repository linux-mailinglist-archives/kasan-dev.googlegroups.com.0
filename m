Return-Path: <kasan-dev+bncBDEKVJM7XAHRBEFKWXXAKGQE7GMBKTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 12C10FC73B
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 14:22:25 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id p20sf4120665eda.21
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 05:22:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573737744; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vet7oILhFsXfhAGaH4OmVClkUhqWyssFJoHCqq1LEz2dEyiNKxLEfGfMLKAgF2VTgs
         FkueIeNcfc3bMPLOG1CUZsEXTdwU3okZL8wgD3wGfFjBMe7/EQlN598o0pxS5MCWe/UG
         dRTNygcg88ZQHmsYNgl9sIAXfLyeu0WMZErniAiFCVE/6/9NjSeJzGpKBZ3pSE/RT6Nc
         eO3T2WPUPwWzThBX1/zbYcSViBDqDgYoO668EQK+996DJp5gUJ5dLgo3CS954w7Z4ajc
         XOcBClzUe+F2MPkcdf+LjKMl8+poMSVqM3UlJvSbBg48g5WH2cN60TCCYNe2EaqxKS7V
         644g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=9b8tlyQLAwbhCCkRP9uP+k73DzlCxYkME/SVdOpXyuM=;
        b=TY9gdfNlltHU+jR9ImPZ+1zyCiODqY2gEME8x8WkCi6s+DicxclpglUZr53MNznl/L
         c2dGefFlSH+6LY1RlM1Cv/6Qndb+kJFNbcr361HDAic3BN4GxWPOtLLYkWrEqrcsMZng
         WuteS4REL7k+h7oaIK4uFvODKoPoSQ5aMw6qwIGKcL69eflCX8we8uGdjii0uzDyusMw
         c8NzfeVosJLswrMxc6A8PKMa/LYRUXozLdNj7n1jKAmOXMthdeYYuByXPFIvo0NL0FIi
         oeKaRdltuZOFz0uVguOtuDoX44zegW5/cMd9qtEr46rYRxXOj5MSxRGAjPr1lpg1FuhA
         20VQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.187 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9b8tlyQLAwbhCCkRP9uP+k73DzlCxYkME/SVdOpXyuM=;
        b=W2WMoJA+mDJGqo64cDCHaWYc/B0jyvLibroXyDPWwwfmCLvyWLoWJW/5M3pnYPiLAm
         WXmrWAEcni+ZFoXz53pl3TBcWSdhxwTg8YnvMrGSQZuF4FjR3blM9z6DBdaoAps2SUJe
         wOzlCFJcg3PoS82n8p8agB7NSpwhaI+WWykTeqAo84g7hhxkxy74TWiaSnNYH5qUPmTs
         k+U8yc3VHxP4LUhZW0M8ehBDWbqHmXOYNz2TTGCg2q9WGH7CMKCQRX9bI6HcVw+qAzUC
         vNBe5QuZiZR9Rl4O2gJsCwd7ZhwDUL/COjBuUGxJhTS9U930YOF+2RspWlme/xNugfmo
         wLYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9b8tlyQLAwbhCCkRP9uP+k73DzlCxYkME/SVdOpXyuM=;
        b=JK4/WnVXQSVl6eF6g/o59Pc0/LM8t7Jx2x+EhmNhhdGOBNMFGfgHMYfbp0F707R33r
         JteMpB0co3t+4oaFzkItCbd9hYLtNUVHbhK8fpJq28LO6q8cVDtIiccsg2gSlg0716B6
         MBea9qZevDZOF/AXXbUrnc+Pee28ws2kSxYXfmwrT7tlxj4D5+wi2+6R0d82MT1HddxN
         gcg410S52wXCS00+8pZT8Wigjvx5CD5AqFsCcK2UdIQY+M/cjs0ek1Lb5W1NigmHYaIr
         ahBmq4UNpwUz/qax7b8Zz+EU4G41XnqkIicGuf1ptX9n8moD3bySO/aiWd4r6l9u8euB
         KUXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU5MHmCD9FIDgONLdgv690aYhKH7OK7rXvCh7H+8BQBuQIb1roX
	U1bw0x+IrJSWAFiPsy9L/Ws=
X-Google-Smtp-Source: APXvYqw7423fxQW5d40sAcezsICKTe/ole1m0xgM5YSyfpGuf3171Htgfs3zfq03Kh2MRMPMIGpXPQ==
X-Received: by 2002:a17:906:fad1:: with SMTP id lu17mr2653087ejb.24.1573737744777;
        Thu, 14 Nov 2019 05:22:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:6c97:: with SMTP id s23ls1763067ejr.9.gmail; Thu, 14
 Nov 2019 05:22:24 -0800 (PST)
X-Received: by 2002:a17:907:216e:: with SMTP id rl14mr8501874ejb.291.1573737744336;
        Thu, 14 Nov 2019 05:22:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573737744; cv=none;
        d=google.com; s=arc-20160816;
        b=FvoE/Z/ofsjHYtUXKVDCWbfctM9iL0k2m67oPO+Bm6BSl6YkcrS/j488oBg742b9Vs
         hD1bGshDRmtQxClsP5R5rQ5SeNIzMNl4gBuSz128G0+xNu4cp+PMqRmyv8Y0NklPPIll
         4RbBI+u7eTDt5rudkQITKrDU5eLRMS5KKEzo4a0b/BFzCzR1J9tE+LNN1l/OQ0aEc3qg
         leV0abU0uwYC4Exj1b44ioDpu7aTxGAv+MB1cP2NwH/7s2rj0cxKvrVHGGxLoeCfXIOy
         uSxkVo2lBQFcSBPu2oNn0MbbPtgaJ//avx1XboPWUcoVU1zS9XVHRBMa9SQP7A+3Z7h5
         X12g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=z3p6NPvrcQMscgnqB0iR1Lf4ZBEjKATfL5BFvQXyvZk=;
        b=IIsfAg3AaXDQu9nann4m15QwxWSivmAPnib+5ohXEO8tgdznVCRAwHRJbEHbIwSaKI
         OgtVdQT6IfllYRdLW07ILqX5tByi4+arqwqLmklsexlCbqtbmiSZvy77NxGCvY/DUvkY
         /PFCRPx+h9QHj4JHBAXU87hIwUgZ1PX+Mvu+E4Nr6eEqUfKEfAVWr00F5GGXPoc846ht
         Sm1r2cJWRgljQ7z7xBe+KzRAxwqZ60bndrUhaaLb3c6NxoH6AQsNGsBVfcMw745VKqld
         A6tVFZhXL+mse4npSux0eHvkY0JgX2MseLI7c+eI4zIoozj2rl13vuP27krL+FYOeFYE
         zTyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.187 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.187])
        by gmr-mx.google.com with ESMTPS id c28si339379eda.4.2019.11.14.05.22.24
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Nov 2019 05:22:24 -0800 (PST)
Received-SPF: neutral (google.com: 212.227.126.187 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.187;
Received: from mail-qk1-f170.google.com ([209.85.222.170]) by
 mrelayeu.kundenserver.de (mreue012 [212.227.15.129]) with ESMTPSA (Nemesis)
 id 1MNfgZ-1iG2g02vQx-00P22F; Thu, 14 Nov 2019 14:22:23 +0100
Received: by mail-qk1-f170.google.com with SMTP id 205so4938339qkk.1;
        Thu, 14 Nov 2019 05:22:23 -0800 (PST)
X-Received: by 2002:a37:44d:: with SMTP id 74mr7154394qke.3.1573737742525;
 Thu, 14 Nov 2019 05:22:22 -0800 (PST)
MIME-Version: 1.0
References: <0000000000007ce85705974c50e5@google.com> <alpine.DEB.2.21.1911141210410.2507@nanos.tec.linutronix.de>
 <CACT4Y+aBLAWOQn4Mosd2Ymvmpbg9E2Lk7PhuziiL8fzM7LT-6g@mail.gmail.com> <CACT4Y+ap9wFaOq-3WhO3-QnW7dCFWArvozQHKxBcmzR3wppvFQ@mail.gmail.com>
In-Reply-To: <CACT4Y+ap9wFaOq-3WhO3-QnW7dCFWArvozQHKxBcmzR3wppvFQ@mail.gmail.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Thu, 14 Nov 2019 14:22:06 +0100
X-Gmail-Original-Message-ID: <CAK8P3a1ybsTEgBd_oOeReTppO=mDBu+6rGufA8Lf+UGK+SgA-A@mail.gmail.com>
Message-ID: <CAK8P3a1ybsTEgBd_oOeReTppO=mDBu+6rGufA8Lf+UGK+SgA-A@mail.gmail.com>
Subject: Re: linux-next boot error: general protection fault in __x64_sys_settimeofday
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, 
	syzbot <syzbot+dccce9b26ba09ca49966@syzkaller.appspotmail.com>, 
	John Stultz <john.stultz@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	Stephen Boyd <sboyd@kernel.org>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	"the arch/x86 maintainers" <x86@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Jann Horn <jannh@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:pL/CGMu04VFwGq8G6lZxZBGXUXJtBbT747RTYeGOL0pMLfIkWCq
 2sDaS6wI54H8oRz9ld5N6cELUubT4jCcoXNCZWu7HMT3dKD8Y1PjS1rav6U5Xnep6YRM8er
 O3k/Ka1BF0IQc+8t3giXxjJVGwoRr15HuocxVaz7ujjxQLkes7Axc2VGk2qYSEjJqfvby5E
 kmvQrKaauuVqhJvPTL4Sw==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:5egtM/Fajjk=:TqwncRMm+v4zlIWpGUNmzv
 tLDJDx1C3RuO+H8r/Bg8BkA7qIrGg1lda5fGf+2VfB8fuFWnGBcHN2f7Aqg9DCtDMNLDSkdGH
 /anakwURsHFLkJiBB8MxdOq06kc3qlB0YNpURnK1UZmCV+ZG/s1dHX/QGlHQ7WdO9ZxFCRrMj
 U0dYxa6rDFDMT7LhzET5ZwMM4piODTz1FrvOGgizJGs+mq+qeq7WyMI40UzNuWjv4+/NUF6Bb
 lI6+VizSN+mZsBc5dmZWxMcKMzGotiIfFM2cBWCUGH+puWdABObKMmSTp3fS/DDbp8kQrFWb+
 baDAEy5FmyGkLDSd9WYOwOe+iO/vXJfCZb/7OK3ftXfg1uOBqb9Go85TLDM2fm/bu4EtWZFTe
 oPQJij47iM4tS4wd5RJzyrugnm5WGqob8VHEWouyWRy3xMc5W2QmkVswofRayV3eS3JI37UPq
 wrthbNehZBcdFkvhGFwt64pBxJDDyzOuLKhEDenhSVA1Aj9LQnPb12/5qf5W0JrGSE3y/aQn3
 3Q727yq6htza5PY9eW+lTf6oMgLT7AgwzA+mQssD7b9WUTIhxbwb6+3sWdNl+n3ItH6bROYPZ
 El+X/9w2qIQ6/QSR0thmhpAWL1FDoZXkpAIExiil76DO0ZAqHjtC0eHMk9InmsZc3LgPRd+XQ
 dUFSbIf5ppd5qVowvhpvsw0398PHfg2miyKTWw5CRTJw5VBfpkI2lWQD8jA1xggFSM4pB8ciU
 HIrupymg0+tKxYjc2zL+F8MlJS+Ng/4DRQrOd+2F55Ghw5Qqba8mrHlyk5Lr41fzVoKAHaC8l
 +RUcp27haf6wYf1WTR6jPQKWgiPKQmrzHHmD32fSbVVcU0n3SeGBmiGBvhROD3uHvYT9IahAi
 WnxKpY6yquTSUV7hiijQ==
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.187 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Thu, Nov 14, 2019 at 1:43 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Nov 14, 2019 at 1:42 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Thu, Nov 14, 2019 at 1:35 PM Thomas Gleixner <tglx@linutronix.de> wrote:
> > >
> > > On Thu, 14 Nov 2019, syzbot wrote:
> > >
> > > From the full console output:

> >
> > Urgently need +Jann's patch to better explain these things!
>
> +Arnd, this does not look right:
>
> commit adde74306a4b05c04dc51f31a08240faf6e97aa9
> Author: Arnd Bergmann <arnd@arndb.de>
> Date:   Wed Aug 15 20:04:11 2018 +0200
>
>     y2038: time: avoid timespec usage in settimeofday()
> ...
>
> -               if (!timeval_valid(&user_tv))
> +               if (tv->tv_usec > USEC_PER_SEC)
>                         return -EINVAL;

Thanks for the report!

I was checking the wrong variable, fixed now,
should push it out to my y2038 branch in a bit.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a1ybsTEgBd_oOeReTppO%3DmDBu%2B6rGufA8Lf%2BUGK%2BSgA-A%40mail.gmail.com.
