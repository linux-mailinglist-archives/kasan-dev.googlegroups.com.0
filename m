Return-Path: <kasan-dev+bncBDQ6ZAEPEQILXJ64WADBUBHMAQEAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B99F8A0370
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Apr 2024 00:33:32 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-41485831b2dsf53918685e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 15:33:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712788412; cv=pass;
        d=google.com; s=arc-20160816;
        b=lJ8cVmrwgFlJKjUykvqCi72aLkhNUyS3VahH0aFRQJbTa0jRvT23N7mrl2PDx3nVKv
         EJwtnpLlUUzDA/Sb1aO1GME6K/96gAcxHWv38DQp3bXz/75PY8emWHDhlRwPjhsQ0CIn
         BTGyS9BRH4NMGb4cpiGyO15jY92sZ99q9sm9Rv9ccCfeTak/dVwSlJXv4vC2TZTJuhq9
         I9lWiLE7QYballZPmy3jg6YLmE/38nRn28R74NhF1Lx+U047rsB2f32dxVXUaVkzROia
         2rZmUgRuVAn+xcCEGWkk0Ja2LSYPBvVRr0vHw3sqT7hAqIbDhUrQ/5Pc83xmbAyvmQLY
         6C6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rpmdVBtN6NOt+RSl2fRfzgaw5OJEFM6qv0tHlCXkBGI=;
        fh=Jwlbkjl8tPKxG5FrDhX5hKOv2WKD32alHhMWUDi4tts=;
        b=wpWP5lelWF4KbFimkuiRb7tPEX1IpeaRV2AHEUQ4NKYXc8Xg9ZZ9AEC7qoIIjO058X
         85WIK1snMxQfHLp1q7dDKsCS3Vj6BSW2G599cbRLsKtkK1iLLSL+2GnVz7U3er6TFnm+
         yGusp7p7lcLv173uhMMplzKBo4l64IXcrrRB3HJg8HcHgahKV8mOumpLZXbWONcXgJ1j
         sLed+fg/wmR6Ciww6t2EBEfrd8Gu8Pc+BDqObeMMcpcieRGIY1SbcEzbfLf/DuabJhe9
         nK0ph+xwX5drdPpQrbGmU4yu68+f+Y+j8ytFYEZ6alVbMS/0KZkzOSO9IEp6YcI7HYVv
         cKwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aM7XuWYv;
       spf=pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=jstultz@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712788412; x=1713393212; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rpmdVBtN6NOt+RSl2fRfzgaw5OJEFM6qv0tHlCXkBGI=;
        b=CQuD/HL40x6ofHewlEPnX5ar5W1Ym5PvwYnoTc5JikMhoTj2Fg1PgnBQzeeie59/o3
         WBtjw5M+JIg8PoL/sU+noDMixkCAgU/D2rz4lcWQphFMp7scwDM4JnVwyCCXQyl8MWSV
         yPjVUGDFm5tJ6zJ6jE/Rval4wIuljfN66lwv1327JqDIwroyCKg0tyRwZC8daMOxJvrd
         HAu3qFPGoa6sxoco9AqtxF6SB/DkCDrnjSvLFvCKb7DKYjsOuK8F0Nh4rMeknHqkNpCE
         yzRfAV4PEZhF4JMI1cFf815m1VlL1wtbiKmwfhpA377AR/VeqeuaDjQmdglgWkW2UYcN
         pmEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712788412; x=1713393212;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=rpmdVBtN6NOt+RSl2fRfzgaw5OJEFM6qv0tHlCXkBGI=;
        b=wlo9q4ta0fsfXxPvCVroYusHGqqXxYbEwAabiGKyyHCCWIKCHqBckhV8mJLC6eYvif
         S14/3JeCvhRfUobv+FmH294vUC0FMe4CzknEMdwXQIIEf80zAnMjGf9PKaOyZTBGa5DW
         KdD3ywHhPlquMfEZWuEHWhN+N5JAlp6Ym8R3/GERpi4DnvvHxYOwWZjiLpFgNMqtFctC
         8dRrkYkJpg/jpTvHVxhZgSzTQGm3iRPrQVMxKU25QqHS7eCnqus3V8CHJTVt9tnZ1vms
         MiUsqIdcQIb75UA+CF8ZuX0Z75PCasFNOO/7bJAk/7+1TRlx6Umspq5RPaWBhru4Hdz6
         OnAg==
X-Forwarded-Encrypted: i=2; AJvYcCXrisfF6A2uTyZQvju/tP4AESXZlMhYFmb/IylnpOgPn31H7PVmtaXjG34k5u9RyD5k3tCJu5Q9HUAP0925lIcFc/r23YKQbg==
X-Gm-Message-State: AOJu0YyHCutnieIXTNYs0bISyJN/mmNSLpWzaOphPMGLfE0AkDPt5bav
	pFBEmBRLYlHepkc6/AZZIDc0xbM6dPY5OtQL6YbEbWFqzhX1rgSg
X-Google-Smtp-Source: AGHT+IH/+MJMB0iycCQGSDPGqFf2l44hYXFv2OjryIl1i73XPN5SH6X4fgt1+JzGfSyX9DljmmpzDQ==
X-Received: by 2002:a05:600c:c06:b0:416:ca75:c445 with SMTP id fm6-20020a05600c0c0600b00416ca75c445mr3171739wmb.18.1712788411576;
        Wed, 10 Apr 2024 15:33:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5106:b0:416:2dc5:d832 with SMTP id
 o6-20020a05600c510600b004162dc5d832ls2462330wms.2.-pod-prod-05-eu; Wed, 10
 Apr 2024 15:33:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWeFCHmA9GKfUvmQYGMeIZ5lR5CGd2UgSthacqK88WoiSooluDsgqChYgTiRNCirqi+SEo/5zzykN4s0OT7kU7MYapDrvUk+SMTQA==
X-Received: by 2002:a05:600c:5006:b0:416:b93e:a19f with SMTP id n6-20020a05600c500600b00416b93ea19fmr3744453wmr.27.1712788409701;
        Wed, 10 Apr 2024 15:33:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712788409; cv=none;
        d=google.com; s=arc-20160816;
        b=ZK1h7DZLx+fDXqxJ+gBEwY5jtyENADJEAEgVo5Taiz1xG7GnUdOSPY76p5sqfWzF8a
         19tZNqEEXtshyhYDoEFPuDefyuTjm1P+5PrHwMCTk7YOZVFl79FhvKM5DnU0AB/A3zhI
         dEEFbYbgDDMHbqoEtLre+PBqsYQLXw8xQHu61MimF6fbA+DdeP6ok4rsdkBI93fs9Ap3
         2JKd59N/jmtkQz2/NahpfjtGE3tKwACgSjJ+m0Hio5ARMrS3JS7fzv6dfBYpgmgwGfBb
         8kA1KG1CLoXiVCxlsYNbg0irQNtXhfj7ntntfXaYz7Hlv4eR5xePkk5FNf7PfaarZYKM
         aYkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=VGcSmVs/OyYWYMT/pav2rCPGZAehytayienznXagGm4=;
        fh=jb6tWA3X2k6kk1I6y0Qa9c42zMVo+nFEHhWIRKpNImg=;
        b=0TBZjxTrBdVneUv7f5mnOall6nPj1DydRZiM/VBYD1a54/sAQ7RYWy2oSN+WhAYFO9
         dRsWgs3WGqymm09Xux/IDAWHxJMVpE9N5C3AGVGNX9k/6en/4BypP7c0GfZj7F7DUBhv
         Ynwl9/fBcSVtdS5AfeQGkv1ONqkoTo3Cow7pd80CvwEIbqFfC6GtwqqIDn06ipWCSMgD
         bjDM4cU/Ia037yxPih0Vnx4ZLK5rDyao7r3PPnzWCUdPZGF6VWZ3r8sEdgpeF9nm4EU7
         cXg4EIDTn1Xj+6BByMdkNanz7SBZsfTZEtOmIpvMultuXs8HKC7o+mr08u0MAhKuKGFe
         JCFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=aM7XuWYv;
       spf=pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=jstultz@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id m8-20020a05600c3b0800b004162d4ff313si189085wms.0.2024.04.10.15.33.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Apr 2024 15:33:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-4154d38ce9dso17675e9.0
        for <kasan-dev@googlegroups.com>; Wed, 10 Apr 2024 15:33:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW/Lzje2Hf5Gfqyom7YmhNVALlSFHMkMYU5w9HV5CqrD781c7rbeZLCWZl7SGMjZAHbDyxtzWlkuwC/FFnoVKa08K5wzspVEwXo3g==
X-Received: by 2002:a05:600c:3503:b0:416:6d90:38fe with SMTP id
 h3-20020a05600c350300b004166d9038femr69216wmq.4.1712788409046; Wed, 10 Apr
 2024 15:33:29 -0700 (PDT)
MIME-Version: 1.0
References: <20240404145408.GD7153@redhat.com> <87le5t9f14.ffs@tglx>
 <20240406150950.GA3060@redhat.com> <20240406151057.GB3060@redhat.com>
 <CACT4Y+Ych4+pdpcTk=yWYUOJcceL5RYoE_B9djX_pwrgOcGmFA@mail.gmail.com>
 <20240408102639.GA25058@redhat.com> <20240408184957.GD25058@redhat.com>
 <87il0r7b4k.ffs@tglx> <20240409111051.GB29396@redhat.com> <877ch67nhb.ffs@tglx>
 <20240409133802.GD29396@redhat.com> <CANDhNCrverCP+nB53XnMKFH4sTvxmtchiLWyGbNW6du=8xOSNg@mail.gmail.com>
 <871q7c3l47.ffs@tglx>
In-Reply-To: <871q7c3l47.ffs@tglx>
From: "'John Stultz' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 10 Apr 2024 15:33:17 -0700
Message-ID: <CANDhNCpas4AQuAquVMVFgN3NCfCsVgg993Kjad8MjvSZAbsXow@mail.gmail.com>
Subject: Re: [PATCH v2] selftests/timers/posix_timers: reimplement check_timer_distribution()
To: Thomas Gleixner <tglx@linutronix.de>
Cc: Oleg Nesterov <oleg@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-kernel@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, kasan-dev@googlegroups.com, 
	Edward Liaw <edliaw@google.com>, Carlos Llamas <cmllamas@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jstultz@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=aM7XuWYv;       spf=pass
 (google.com: domain of jstultz@google.com designates 2a00:1450:4864:20::334
 as permitted sender) smtp.mailfrom=jstultz@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: John Stultz <jstultz@google.com>
Reply-To: John Stultz <jstultz@google.com>
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

On Wed, Apr 10, 2024 at 3:31=E2=80=AFPM Thomas Gleixner <tglx@linutronix.de=
> wrote:
>
> On Wed, Apr 10 2024 at 15:21, John Stultz wrote:
> > On Tue, Apr 9, 2024 at 6:39=E2=80=AFAM Oleg Nesterov <oleg@redhat.com> =
wrote:
> > This is working great here (on both 6.6 and the older 6.1)! Thanks so
> > much for fixing this!
> > One nit below, but otherwise:
> >   Tested-by: John Stultz <jstultz@google.com>
> >
> >> +err:
> >> +       ksft_print_msg(errmsg);
> >
> > This bit is causing the following warning:
> > posix_timers.c:250:2: warning: format not a string literal and no
> > format arguments [-Wformat-security]
> >   250 |  ksft_print_msg(errmsg);
> >       |  ^~~~~~~~~~~~~~
> >
> > A simple fix is just to switch it to:
> >   ksft_print_msg("%s", errmsg);
>
> Can you please send a delta patch against tip timers/urgent?

Will do! Apologies for not getting to test and reply earlier.
-john

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANDhNCpas4AQuAquVMVFgN3NCfCsVgg993Kjad8MjvSZAbsXow%40mail.gmail.=
com.
