Return-Path: <kasan-dev+bncBC3ZPIWN3EFBB5UQZH6AKGQECOV7FRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id E12302968A1
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 05:05:26 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id l22sf819wmi.4
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 20:05:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603422326; cv=pass;
        d=google.com; s=arc-20160816;
        b=wdWgP/LXUqvtmjD8QMrty3OpEE+XFLt2YlHelqeEZb1gOgc+gwLaXPDG1UPMbq7m/7
         9RTua1g4hXowopyuTvs0vAn9nA49PFvRFkH2Tu3xaHDXtxRZTku2Sn/feOEUZ1mj1FXx
         o7JxJG/JxLmNkUtlS/LjfqQqJjQRInVoAOutPClm7PQjJvqGq9FLVorHR8w2TD8Ae6kX
         jx0oHj/4taMqLPOwgwkx2c0ohErrbpinO2jBLvDVzoNbLMTiaXFdJfewWSRhrDK9Vmr6
         Pw9d/KbIeiNLBIJrqrr5r+CKM/yEXdZb/g5yyhmtl2vryeNI5nqqyRtZYEnBqKU8DTtQ
         NOcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=PyEVZYt2spuQlcMTKd4ETS8dlj4gNu6GR9k6pDfoFWw=;
        b=vGzoWb+IOpSUFZfrs77oCISyq6KD/kM+jhy3/1cqTuksPf8HoGzl3ttY7MmOLqLgPD
         c0VwhfnHyjT02+apsRm/8nhwqFkayxlXpc/SqZbc8ImM27uOHYWHOs9V8lbOgxAV+1Og
         +YYfLW50SOEmmF4lF+ZDygqTrlXnFyxl1kAbjlyFanZFJVhdoSoVnO+1Wwxof8PRUOBd
         AylHoub4Oy0WxM6fE1vMEuHTrHj+xnqtoENc1RttaWDUg17CFIXZ1WwJ/GxNLF14sGVK
         Leg8STHzxoEMLgS11dFstcKDNye7U1ftfl6i9Sz3pBkienfZXDAG+zvPj4WkVfN8CnVi
         tbKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=dvQpU+FB;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PyEVZYt2spuQlcMTKd4ETS8dlj4gNu6GR9k6pDfoFWw=;
        b=l/57bUkFlGmwSufgGPltF2hF7T3feycXeqTtLwSVAXqdH8HAa5kZ+t6Q4lpx/T8fqb
         FlgA+kXUlBlJs0UoCxjzsfnp1bJnW++wwlLjVeTWXs656xDcdVgR4Ly/yu4c+FgPyiLl
         v6gXRUEkooQXlS4T4ZfkAAuj67nBIMUl0HYk2hyZ0tRWIaOychZ9vjZWIaddxDYiMXYp
         LZn7YyK758b1KsxSBujHvoYPIuprNyL1mA3BNpPqbGY+AAv0dKMwHPc4m3xjzmzOd/x2
         vsLiBSTK6Yy5PDz5uX/TFkZxZvtGJv4CQUvnqLK2O6M1tiW8Fg8E+kzquK8bFqYFBgjA
         /D3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PyEVZYt2spuQlcMTKd4ETS8dlj4gNu6GR9k6pDfoFWw=;
        b=hdzyHOmLiFh7nAcynMsvCeD3iXPHfqAZm7WXA/9oEXsBg92xAzi8LjQsHbnLTalk4d
         sl+7x6/ysoXc8vrtSIhq+l5qurVSg2kZccI1yWG/5u3WNfrEoxmwp2OYGNqjEKbVSPnT
         CJK2dcHTKtjGPIjb+fLnNYEv9qw7maMVmYtLfRvCWaI9oxat33Nni9UB8zvudazqbLHR
         q++PhXRUUShijI0CO54kxDPL+1ovVfGgMs2q95bj1Ca/ZSCamlrptmKqjhCzyF3QQSC1
         HrnGt9z7WpGJRcN6vuF1CSd3ynrBy0XO9WFmji6MX46qrAcQGRv4oIUemi2t+zsu4s19
         Rv0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533WdhdeeEd1J7T7Te4LkOblIQrxvpDCRChOxFx3mKZKQn699xps
	J/o3PUNuEZrx8OphkBgM6yg=
X-Google-Smtp-Source: ABdhPJwRMqW0PzZo2C5GhyOXFZYcrkWQhWteOJSfv7bt+uFV6pYyOUyioccaLO3rfQnG4Og5TyM6uQ==
X-Received: by 2002:a1c:1b46:: with SMTP id b67mr90312wmb.82.1603422326643;
        Thu, 22 Oct 2020 20:05:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:82ab:: with SMTP id 40ls53386wrc.1.gmail; Thu, 22 Oct
 2020 20:05:25 -0700 (PDT)
X-Received: by 2002:adf:fdc7:: with SMTP id i7mr239120wrs.198.1603422325592;
        Thu, 22 Oct 2020 20:05:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603422325; cv=none;
        d=google.com; s=arc-20160816;
        b=i5UubtQh+GJi6Q1Kud8ZB/uvZ9/5oQD5BVJPwYFCa2oVCT5tTsHC1in40XXbpnUAhP
         chCYAfM3eK4BJQfvg2WOhXWZrMD0V6/LyQ/PelV7tb3krSivawZOcv9w2kQ4Yeek1R+3
         SiddxQHW2NMLY7V8hDvbfCw1qNBitKSQYJ95dUL7hu8UJGO/1W1UUMXXn7RpNwVqLCpc
         0Oic5eLcex5ru6veX8dOyvY5EbWWtEurxEC/VgajGI+iZHAwcDMUTy0Ob6oROVRDZQ3V
         HrWWbs1nVgM8/ftUKELQFJH9TwBEXnsgXbBQEWt8nOPuILPN+4kFTgUkDi4Bp3jDLwGp
         bnKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Na94wtC1BhSlnxPRS1UAdX72oiIY6E2rGP3IXkaaAPI=;
        b=SnTGrL6XNw6vbGu1rVr5gaXm2J7GfuDf9+ZECOLBw4kcFlN++oPn6y1Wc1zz/fKuGu
         bit13iAHKwnXa2CAqX1ifIcKRbqZk1Ut65r1y/T2FRkEeSUcOrA2HO6SbVkkUESBCLmU
         c+fyxw5FH6u6VtrwuQqy93/dAFDT7nvaNFBBIzfpaWpS7UHMzjZQYcLrUIB4F2QXNZcM
         KLAdqG72JNGBpbmh/401nAII8BMaqeJv/poTi5z3OuInb+jGLoVATyoTFYo/8WRavk2g
         fWtUc26rOV/luJY+v+q2E320ffbsHTvBwfBmpAz7F1PasYYGgiINwlje5GJPaOKBajl2
         62tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=dvQpU+FB;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id e5si8550wrj.3.2020.10.22.20.05.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 20:05:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id a5so4160641ljj.11
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 20:05:25 -0700 (PDT)
X-Received: by 2002:a2e:81d4:: with SMTP id s20mr12268ljg.232.1603422324695;
        Thu, 22 Oct 2020 20:05:24 -0700 (PDT)
Received: from mail-lf1-f53.google.com (mail-lf1-f53.google.com. [209.85.167.53])
        by smtp.gmail.com with ESMTPSA id u26sm14104ljo.40.2020.10.22.20.05.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 20:05:22 -0700 (PDT)
Received: by mail-lf1-f53.google.com with SMTP id l2so303519lfk.0
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 20:05:22 -0700 (PDT)
X-Received: by 2002:a19:83c9:: with SMTP id f192mr33971lfd.148.1603422321812;
 Thu, 22 Oct 2020 20:05:21 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
 <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
 <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com>
 <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com>
 <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com> <CAEUSe78A4fhsyF6+jWKVjd4isaUeuFWLiWqnhic87BF6cecN3w@mail.gmail.com>
In-Reply-To: <CAEUSe78A4fhsyF6+jWKVjd4isaUeuFWLiWqnhic87BF6cecN3w@mail.gmail.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 22 Oct 2020 20:05:05 -0700
X-Gmail-Original-Message-ID: <CAHk-=wgqAp5B46SWzgBt6UkheVGFPs2rrE6H4aqLExXE1TXRfQ@mail.gmail.com>
Message-ID: <CAHk-=wgqAp5B46SWzgBt6UkheVGFPs2rrE6H4aqLExXE1TXRfQ@mail.gmail.com>
Subject: Re: [LTP] mmstress[1309]: segfault at 7f3d71a36ee8 ip
 00007f3d77132bdf sp 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: =?UTF-8?B?RGFuaWVsIETDrWF6?= <daniel.diaz@linaro.org>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>, Stephen Rothwell <sfr@canb.auug.org.au>, 
	"Matthew Wilcox (Oracle)" <willy@infradead.org>, zenglg.jy@cn.fujitsu.com, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Viresh Kumar <viresh.kumar@linaro.org>, X86 ML <x86@kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, lkft-triage@lists.linaro.org, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-mm <linux-mm@kvack.org>, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Christian Brauner <christian.brauner@ubuntu.com>, 
	Ingo Molnar <mingo@redhat.com>, LTP List <ltp@lists.linux.it>, Al Viro <viro@zeniv.linux.org.uk>
Content-Type: multipart/mixed; boundary="000000000000eb07d805b24dd94f"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=dvQpU+FB;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

--000000000000eb07d805b24dd94f
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Thu, Oct 22, 2020 at 6:36 PM Daniel D=C3=ADaz <daniel.diaz@linaro.org> w=
rote:
>
> The kernel Naresh originally referred to is here:
>   https://builds.tuxbuild.com/SCI7Xyjb7V2NbfQ2lbKBZw/

Thanks.

And when I started looking at it, I realized that my original idea
("just look for __put_user_nocheck_X calls, there aren't so many of
those") was garbage, and that I was just being stupid.

Yes, the commit that broke was about __put_user(), but in order to not
duplicate all the code, it re-used the regular put_user()
infrastructure, and so all the normal put_user() calls are potential
problem spots too if this is about the compiler interaction with KASAN
and the asm changes.

So it's not just a couple of special cases to look at, it's all the
normal cases too.

Ok, back to the drawing board, but I think reverting it is probably
the right thing to do if I can't think of something smart.

That said, since you see this on x86-64, where the whole ugly trick with th=
at

   register asm("%"_ASM_AX)

is unnecessary (because the 8-byte case is still just a single
register, no %eax:%edx games needed), it would be interesting to hear
if the attached patch fixes it. That would confirm that the problem
really is due to some register allocation issue interaction (or,
alternatively, it would tell me that there's something else going on).

                  Linus

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHk-%3DwgqAp5B46SWzgBt6UkheVGFPs2rrE6H4aqLExXE1TXRfQ%40mail.gmai=
l.com.

--000000000000eb07d805b24dd94f
Content-Type: application/octet-stream; name=patch
Content-Disposition: attachment; filename=patch
Content-Transfer-Encoding: base64
Content-ID: <f_kglo76xr0>
X-Attachment-Id: f_kglo76xr0

IGFyY2gveDg2L2luY2x1ZGUvYXNtL3VhY2Nlc3MuaCB8IDQgKystLQogMSBmaWxlIGNoYW5nZWQs
IDIgaW5zZXJ0aW9ucygrKSwgMiBkZWxldGlvbnMoLSkKCmRpZmYgLS1naXQgYS9hcmNoL3g4Ni9p
bmNsdWRlL2FzbS91YWNjZXNzLmggYi9hcmNoL3g4Ni9pbmNsdWRlL2FzbS91YWNjZXNzLmgKaW5k
ZXggZjEzNjU5NTIzMTA4Li4wZjNlMjAyZDllZWEgMTAwNjQ0Ci0tLSBhL2FyY2gveDg2L2luY2x1
ZGUvYXNtL3VhY2Nlc3MuaAorKysgYi9hcmNoL3g4Ni9pbmNsdWRlL2FzbS91YWNjZXNzLmgKQEAg
LTIxMSwxNCArMjExLDE0IEBAIGV4dGVybiB2b2lkIF9fcHV0X3VzZXJfbm9jaGVja184KHZvaWQp
OwogI2RlZmluZSBkb19wdXRfdXNlcl9jYWxsKGZuLHgscHRyKQkJCQkJXAogKHsJCQkJCQkJCQlc
CiAJaW50IF9fcmV0X3B1OwkJCQkJCQlcCi0JcmVnaXN0ZXIgX190eXBlb2ZfXygqKHB0cikpIF9f
dmFsX3B1IGFzbSgiJSJfQVNNX0FYKTsJCVwKKwlfX3R5cGVvZl9fKCoocHRyKSkgX192YWxfcHU7
CQkJCQlcCiAJX19jaGtfdXNlcl9wdHIocHRyKTsJCQkJCQlcCiAJX192YWxfcHUgPSAoeCk7CQkJ
CQkJCVwKIAlhc20gdm9sYXRpbGUoImNhbGwgX18iICNmbiAiXyVQW3NpemVdIgkJCQlcCiAJCSAg
ICAgOiAiPWMiIChfX3JldF9wdSksCQkJCQlcCiAJCQlBU01fQ0FMTF9DT05TVFJBSU5UCQkJCVwK
IAkJICAgICA6ICIwIiAocHRyKSwJCQkJCVwKLQkJICAgICAgICJyIiAoX192YWxfcHUpLAkJCQkJ
XAorCQkgICAgICAgImEiIChfX3ZhbF9wdSksCQkJCQlcCiAJCSAgICAgICBbc2l6ZV0gImkiIChz
aXplb2YoKihwdHIpKSkJCQlcCiAJCSAgICAgOiJlYngiKTsJCQkJCQlcCiAJX19idWlsdGluX2V4
cGVjdChfX3JldF9wdSwgMCk7CQkJCQlcCg==
--000000000000eb07d805b24dd94f--
