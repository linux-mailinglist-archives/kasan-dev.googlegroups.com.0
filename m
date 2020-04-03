Return-Path: <kasan-dev+bncBCA2BG6MWAHBBOW4TX2AKGQEDD6DPOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id C8C7119DC71
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Apr 2020 19:11:23 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id 78sf6429040pfy.22
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Apr 2020 10:11:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585933882; cv=pass;
        d=google.com; s=arc-20160816;
        b=AWWtvbkY2VCCbDzbpsfpx48v7vac7UevJAkagmuh1xPkXouElh9xCGAEQCduuijxVI
         1knwHoQDJ6ppr0h1UJgct8pqbIUnFUi9bB1Cw79JvZ9cuxJ65NvfAmGyt04X69NEy/ck
         s5Ft8o2mazxOrhoorYj/vdxiVyPzYoRTc4gi+q54fFIzI76t22Ct03lp8anc+Xs+sGye
         b58qijkdTlGC+OCTFnHAh2BXSNbI+iFHZLHIj/DNFnP5WzoBTRGw++h3BKJuFZ2YNZki
         I/tOj22zIOtX+Q+WL6AYR77OmykAiqu0sIODjGmFOEpjqrfpkSHqRNf2ljCyRojK1PQz
         JNVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7w+5NIKCMkTJYfxgwrt/eq1jAv8XLNbb4m3WOG072JY=;
        b=Lu+TdNJZ7V51sTXo5WKdDNOK2DNEzlqdNvzPfKiKCT5BrwAQb8Kb1xaJvhGy0LVZG5
         t+NO4YMAGokBx9HKXqzViZMiBagWldsOPaHE8p8QLjCXbQeW20+DvgSRQMJNVLsdHE3A
         eGpDBK4eRo5ZZKlX4PNilUvvsH02C3bNClNcLQABJCWafOfoVp3wrEHA5BNn4J47lxJ9
         b8UPMdobNTw3LS6hYg8fJ4jLuXJRpYG/bdSrGAF+XEuDjkliI5eOVbW6x4xU+wpEDJBH
         SB0XSmJEotLjNGP6/q9p6V5tjOdUAQMM31KZiKkfalO5EOb6ouWFF3xZy1p/fhwQVmd0
         ttEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DyKtecke;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7w+5NIKCMkTJYfxgwrt/eq1jAv8XLNbb4m3WOG072JY=;
        b=NUqAOCJ53u99eU36D9OX+j3HS0QhDE+nKOPRs4t45+//Enaz4Bd876pMnI71dHOcEG
         l8JtR00aSBPWaVy/ClY1+B5ArJg3VvuRqP+lYF9Dttpw6q3q2FTJSbJWTlXjul88IZwt
         cXdqyKm6i6ugxPRMWFXSheiJ0qVhZ5EgARV6RnPp1X5pece8lrnNZeDqvY0lH50Z8PZZ
         C9B1FkyP+yAXuf8OKLeAu6ahpruuCzswniJDo6zDPH9JaHLQYWi7/AjRe5azrqjmmA2Q
         VntJ4YwyK/zW8vEv9cQywF4NbZ+wq1iGNQaId+A8NeCfE8A/CYhfvm4ld207cc/TuzRw
         ivdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7w+5NIKCMkTJYfxgwrt/eq1jAv8XLNbb4m3WOG072JY=;
        b=pC7r/2yqVmMUcaFwVrO0LNygLHPEXClJlZeFJldHSgR/xHWHkYTSuqg+v08FIZXTuD
         M9JdCC0YcqbUgpSTi1i0oNgZXX6E9wQfltQEYy9iqEIikeV1qzYpc+rqXmuakgdJZc3U
         07wl4/+2fcPZo2Zi5hhLlEvHnMSMU2cb+jhjRYuI6wmRE7KSCK/wZtz1IuMJT3VNlkQD
         Cyu2bpyeb4605ufAmz3tgU5s8BrJvEM0t2Iyv6rFkRV68gqgVWet3H3a2Uzt67z0WEZi
         Fe0OufvZ/JnDFQ9OOaxAAh6aDw3SjfChsa6ElndpWXjeCRPiLHGi6kh6Z60EEfgXywm5
         R+2Q==
X-Gm-Message-State: AGi0PuaIzqi1dXd1ZkYmD/G4kU5Kgughp31sPrMa3Hp9cBITZCf/I7fT
	yPgUmL2HOR2UVMouJ0brICA=
X-Google-Smtp-Source: APiQypIPlhS03JZGqM9PMBrzA+MzAN5kf/+j1b9xeMTlpLwQjLpQvn4xQ0Po0He2BrVAWsTWA8uf3g==
X-Received: by 2002:a17:902:9048:: with SMTP id w8mr8600865plz.24.1585933882160;
        Fri, 03 Apr 2020 10:11:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:16d5:: with SMTP id 204ls5316550pfw.3.gmail; Fri, 03 Apr
 2020 10:11:21 -0700 (PDT)
X-Received: by 2002:a63:3d0:: with SMTP id 199mr9500510pgd.220.1585933881656;
        Fri, 03 Apr 2020 10:11:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585933881; cv=none;
        d=google.com; s=arc-20160816;
        b=i5/mNkstCWoSCidGVJPLubFyOoflDYIIL6OaMoojems0/ZAVI+g7797Kd0s2k95dBF
         /8LH+969ct/6gEprXqevbV8/OYEIlRqPHwJgsPedEtmR2iqse19bK5/l6mWWF/efIwI9
         ILKKlMM8ovP4bxfIjccdgIFduQB+e28VRSTCyh6lkD+yjqZAPS/J9SZxdxHI8s4rMb3W
         rXVuY3EKUWxrtdYacFuKEiZ2VMueRXT5R4rLO3LtRBWUi5nZIzaQvPE/RRoJCT2bXmTV
         XSdLVynZiWTUB8gn/wKMgi3erP5g8CnGn7gIkc6+La2+VEFL2vYtFaqUK3RX4uF6qOeR
         ujJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Do8qIdF6vQT1e9Pt11DpfMfF7NFSyvJ9YAoinVPJ4B0=;
        b=nf+J4E60JtFFa+b/k0/eChflZbfXw3bskPZU5gsjQardrf8nRaFAxdWKBdMZfiJ3eW
         uUqLz7WcQpWhcwUM0iXBKroTrIorv3fvi9uc7gpX8NhMgix7+MG/a+NbP80HMr6WXhRC
         I0Lj4ofr0Lpkh7h+Cv3j2qRW+/6LemJKL/Vgd/f9xOQy1spgQQ4sWB5zG7bJ94ne9T2l
         Gha8PRjfDiUi6sTjD2MXeC7wvY5/8xcSrwmmhIZ6PI1s6Pw33WLE6hysngzayN+41AUQ
         3I7f6Hexb/xHLmbXHiIxbqUBMbWExrwRtid7peHbnp20oW6CuW6a29ifpk9aok3bdXEB
         BttA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DyKtecke;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id i10si439690pli.0.2020.04.03.10.11.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Apr 2020 10:11:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id f206so3781602pfa.10
        for <kasan-dev@googlegroups.com>; Fri, 03 Apr 2020 10:11:21 -0700 (PDT)
X-Received: by 2002:a63:d049:: with SMTP id s9mr8754031pgi.384.1585933881177;
 Fri, 03 Apr 2020 10:11:21 -0700 (PDT)
MIME-Version: 1.0
References: <20200402204639.161637-1-trishalfonso@google.com> <20200402204639.161637-4-trishalfonso@google.com>
In-Reply-To: <20200402204639.161637-4-trishalfonso@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 3 Apr 2020 10:11:10 -0700
Message-ID: <CAFd5g45owC+D+K4RuppmyTJ+d+NGRL1CpuciXwXYvmtBfXnXYg@mail.gmail.com>
Subject: Re: [PATCH v4 1/4] Add KUnit Struct to Current Task
To: Patricia Alfonso <trishalfonso@google.com>
Cc: David Gow <davidgow@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DyKtecke;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Thu, Apr 2, 2020 at 1:46 PM 'Patricia Alfonso' via KUnit
Development <kunit-dev@googlegroups.com> wrote:
>
> In order to integrate debugging tools like KASAN into the KUnit
> framework, add KUnit struct to the current task to keep track of the
> current KUnit test.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g45owC%2BD%2BK4RuppmyTJ%2Bd%2BNGRL1CpuciXwXYvmtBfXnXYg%40mail.gmail.com.
