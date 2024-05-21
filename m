Return-Path: <kasan-dev+bncBDW2JDUY5AORBPUQWSZAMGQEX4JHZFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B96A8CB4D6
	for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2024 22:46:55 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-34d9deebf38sf8222136f8f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2024 13:46:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716324414; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZHDoLyuB1FE2LoQ0UmPyXCVF4RxjyT1lHIV0wI2G6Ykf+0KmOoIq0qarhqBSVxo6zA
         s5vKj5wl8+RUudDLBH4AQeH4kBH1F48VTuJ2wo5UDTYr+zpFOCyG58bQPP1cMK3w6ZvV
         KRWX/QuDsAXa+IChy0PMd8uZmgSPfEQYyhDjKOLtpYBhF5LGDqK7dJ6sE91Wd31k/sR8
         OXmoWxL0hoUL3YCqgjL5c8KcRj+/VP2HLtXi5m5/maK0UEe3giMJk9QVN7XLpK0KwF/C
         1g/lXAyOCKC9TPe7fMTDXdNy+DblmvxM9mLab1Em+UGYNOgfbUJ2SBfrFDXeMjT2Tj52
         HBjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=d2w0Gn76RSD3O9HoUtX91qGv0hQ70LcKK+JEPFlDiZc=;
        fh=dXpZrNn7fuoCZA1wAObEy4mzwBABWHdWmq5aBq1kH2M=;
        b=H0iXya3urfg5tJ5Eq+7LejuOmymJWj5O/EE0CYmFJQaU329J6qETyntgY04Tm61rem
         /sBZO+apnxWLkhw4Ceg4MeoveG5y1WwJdILAPZh1kxDe246mRuRULr6+KWaQ8XXlU972
         QWQL/kJfXqAdnIgvDt8RbE/oeiivF7HVQNMN4p592DQ0V7lXHDH0lmeGhrJ8aSmJ94un
         zYcofL00zrJK7EBJkqEDTPIfVfLKlBQpthea/Xqq8H4GVB+VrwztOW8itiuEARDLEkBe
         zvvTEyn+mErM/6LXuynQw5KjN0RPH7q9kf26krcxkxLWlVRx1oIa3rG7c9mLzvo+B6Cc
         8vNw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ERQic6FG;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716324414; x=1716929214; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=d2w0Gn76RSD3O9HoUtX91qGv0hQ70LcKK+JEPFlDiZc=;
        b=B7tnTZOMPJWNGkiRAcdHdavarX5K7ZUhPIdSmROYR2+BV34LIDqTb3zf8xIVwMH03j
         G30Skt9Bz81p4hcEb9ikoC8VU/qlvDomWSRYI8C6MMe60CLjamWaGoRd8+mpOJqyaG98
         kSSvR324sMc6/hMZMuD9XryCzeJvLjVCsJp/4qy2RqUlcEUSHli6wTjRlr2Bq3rLdH1G
         LDDSc5ia539eVPg+4t5Wzyh49vtRe2wcBHLQo48eE9pf7pda/lezW7/02L8e/OY1Q8O8
         SruWdn57nP68UdKZ7rqvVQMd2jbdAfsa7zY4KFsp0ZSwv10TD4Sx5fIcqzAVO5qLaW2X
         0xEw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1716324414; x=1716929214; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=d2w0Gn76RSD3O9HoUtX91qGv0hQ70LcKK+JEPFlDiZc=;
        b=kG4qQJcbfAX0Uvj+PnVvU4i60Caq7pw8fUx6H0V7dhiTo17r0TQqdPzMjJhv1id9qz
         s2Vucfr+QxZ+WmsnS2qgiDlb7mWX1oQXkC/C8P2LfuEsjITQ/k2uIPtAZ773Z44oL6zj
         acssgATh6EN8EuqjYtLjwzEWNWQkRVcCWT08ckrvrm1mVnMiSO+9qGm4DpMNNeAAAKTh
         3gxrX1YVb3F9yX11lqU37wgNek7ocxVQUWwb7Z9zluK3zYhTng5fzenvI5cMQznxaAbV
         gXikByxCMRs6tLt+Y8gPBVt++3CPgfIMwatei09VUYb4svQj91VpK8eMLu/sDLAiTSS+
         6+OQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716324414; x=1716929214;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=d2w0Gn76RSD3O9HoUtX91qGv0hQ70LcKK+JEPFlDiZc=;
        b=DnBQafq+ruPKO1k1nnZ9rsQMB8xLnfJCIBjYv/0iTVICEy5/0GNuixVEa8Q4dgLfk0
         YG1tMSyFkN6LgUwcJHA2cruouwvKFg0eNjrP7XxWeyHbxamE7O35dnCRPWl0anxGVn7A
         jDKKK/g+980U+YlO/nBWenXzeji4LszCT+jwmSaGoowGQFgMHXHeM2KASrEShJCXCOyX
         VFcOP2fUQZpae9slriUYyWz/3BTuiv+kBJcZjtFkHPzmOIxJIeFaSRT3LUXWgCT0+sBZ
         5+gHEcms24gEL+toKw8ZY8t15tQJSi0iOmM7QABaKRAYZ7WHTcc2znF7GyK4Y8m2fTxB
         /Mjw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXV9SVZU3Y2eWm2T/+sJ3/4Qtf+Qha03pD0mZPuE7TQXC1+lNty7in6y0NDMV1kXCm6+IOeRcavYwRQJb3uJuWJPTT9cC/HJQ==
X-Gm-Message-State: AOJu0YyrIp+Xj0uwe19r4FYtSRDabi9FUKvgDCpcMuaZR5VSd+4T64tR
	qvkdpS+F85tvQdP5jFXVQvH5pOiZBkHLIpmOmGnnwDxCjASpOgzm
X-Google-Smtp-Source: AGHT+IGb6ZNqiEAJcAzYaxj79Kp40TWq5AVJA97OwTwHQXPauJ6DI6ayuZob1/j0FYRZ2AOxyhrBdQ==
X-Received: by 2002:adf:f5c3:0:b0:34d:745e:4987 with SMTP id ffacd0b85a97d-354d8c85c25mr90742f8f.15.1716324414444;
        Tue, 21 May 2024 13:46:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6e0b:0:b0:351:d90a:5483 with SMTP id ffacd0b85a97d-351d90a5775ls1073102f8f.0.-pod-prod-08-eu;
 Tue, 21 May 2024 13:46:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWuCKX/CYYXXsLlydD58Ly47SuXyTUwc1bDW0rmh8pp2bWL1K1q9EkhHVDD+8R68KqO8/aIFp8YK8FgM7G74tGSomEEbwxz7gGOIA==
X-Received: by 2002:a05:600c:21da:b0:420:ec6d:26c8 with SMTP id 5b1f17b1804b1-420fd2fe9bdmr130785e9.12.1716324412408;
        Tue, 21 May 2024 13:46:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716324412; cv=none;
        d=google.com; s=arc-20160816;
        b=z8nQPAwwSSUjrOhaCUOheyBRMb/WkvAdb+L7T2hYXNl9YIdFRjtgKeQI/EKvugKBkm
         MdsyK5LBi+9ak80iL5vnT1zXzGpc8gjYgJaOCCSUm+gBEDZ4t2KeKEKLfl7jUDXdfH47
         z47tt9U4A4ibbzWD5H2NDpn+u2jDbj4gS7Pj9znWq0KFMzbOrOkXJLqffmGgqoslUbsZ
         WBollkhHzj85MBxEyD8E83IMGmAE/b3BnYe7KW7vkV3W615cnA3BcbFNZq7kRinK0Q0N
         uwOXHu6kl6JEjgarmgtNVRai7jMoyswD5i/owqs9XlmoAQ/ewXeoS3bG68cE5Ai4i0vM
         8jmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RwCS/BKSDM1f7z64QrAXpA4rfh3F6s6yn7di6QgXgHU=;
        fh=CshZD6ZPR65ynvLsefMridfyjeNLDEFqgJuW2uuqI/Y=;
        b=jntvKCZg6McYVWuUZt4EAHfUJ0URBc5B1CjhxdMnaS6wYDgqn0axeHDYawv/EVltBb
         Z7yv+0BWR/6Xpoy5Gq7TgOo4mjtOlio1pTERPZdQWQrFV00u8N6rthQ/dRWiC+KcwgCw
         lRVOtx2600llcyc4Y2nQ+jqh7QFz3wX7LLERiXFeqfDpw02ABDjwgU8/QN7vqFbPwBfW
         i+U9YfDwzN7ArVD5MOdlkeiwxHYFOOJXH00iPACC9xtSoewrCW9Rte9xRPgaGYSTM1rr
         UkSz7pf3bbj6UDh4rJTNjmTmDvUSuAipoAMXGAGPLRKzfLGFECyXE9D0GLFb15r/+IFp
         vcfA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ERQic6FG;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4202f27fcd4si2981935e9.0.2024.05.21.13.46.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 May 2024 13:46:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-41fd5dc04f0so822205e9.0
        for <kasan-dev@googlegroups.com>; Tue, 21 May 2024 13:46:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXQlh2NMi9ZhXL/33RXpT/MRCkv/tjMCGPbhcR3mpfmcW2lwzWe9WoYHirdMLmEh6XYgUlGjrndaiWeIJ2ooON/RgJC9y3F2fHAzg==
X-Received: by 2002:a7b:c30b:0:b0:41f:bcd7:303f with SMTP id
 5b1f17b1804b1-420fd30e480mr156395e9.16.1716324411817; Tue, 21 May 2024
 13:46:51 -0700 (PDT)
MIME-Version: 1.0
References: <20240520205856.162910-1-andrey.konovalov@linux.dev> <CACT4Y+bO03Efd48XW7V6F2D9FMUoWytV8L9BL8OK2DR8scJgmQ@mail.gmail.com>
In-Reply-To: <CACT4Y+bO03Efd48XW7V6F2D9FMUoWytV8L9BL8OK2DR8scJgmQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 21 May 2024 22:46:40 +0200
Message-ID: <CA+fCnZcd2nJ6XLmJcPfwVJf9wUcHqWjYnafDdV8pmm3HpjY7Wg@mail.gmail.com>
Subject: Re: [PATCH] kcov, usb: disable interrupts in kcov_remote_start_usb_softirq
To: Dmitry Vyukov <dvyukov@google.com>
Cc: andrey.konovalov@linux.dev, Alan Stern <stern@rowland.harvard.edu>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Tejun Heo <tj@kernel.org>, 
	linux-usb@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ERQic6FG;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Tue, May 21, 2024 at 6:35=E2=80=AFAM Dmitry Vyukov <dvyukov@google.com> =
wrote:
>
> On Mon, 20 May 2024 at 22:59, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@gmail.com>
> >
> > After commit 8fea0c8fda30 ("usb: core: hcd: Convert from tasklet to BH
> > workqueue"), usb_giveback_urb_bh() runs in the BH workqueue with
> > interrupts enabled.
> >
> > Thus, the remote coverage collection section in usb_giveback_urb_bh()->
> > __usb_hcd_giveback_urb() might be interrupted, and the interrupt handle=
r
> > might invoke __usb_hcd_giveback_urb() again.
> >
> > This breaks KCOV, as it does not support nested remote coverage collect=
ion
> > sections within the same context (neither in task nor in softirq).
> >
> > Update kcov_remote_start/stop_usb_softirq() to disable interrupts for t=
he
> > duration of the coverage collection section to avoid nested sections in
> > the softirq context (in addition to such in the task context, which are
> > already handled).
>
> Besides the issue pointed by the test robot:
>
> Acked-by: Dmitry Vyukov <dvyukov@google.com>
>
> Thanks for fixing this.

Thanks for the ack!

> This section of code does not rely on reentrancy, right? E.g. one
> callback won't wait for completion of another callback?

I think all should be good. Before the BH workqueue change, the code
ran with interrupts disabled.

> At some point we started seeing lots of "remote cover enable write
> trace failed (errno 17)" errors while running syzkaller. Can these
> errors be caused by this issue?

This looks like a different issue. I also noticed this when I tried
running a log with a bunch of USB programs via syz-execprog. Not sure
why this happens, but I still see it with this patch applied.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcd2nJ6XLmJcPfwVJf9wUcHqWjYnafDdV8pmm3HpjY7Wg%40mail.gmai=
l.com.
