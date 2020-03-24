Return-Path: <kasan-dev+bncBCMIZB7QWENRB3W747ZQKGQEDRVRPVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 15548190C8A
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 12:33:04 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id q17sf5065256otl.20
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 04:33:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585049583; cv=pass;
        d=google.com; s=arc-20160816;
        b=wTQDapUWRkyQF7w3M+s4EEC6yJ/lASsWYG1EiWsXPBy9kA9nKrUEeCWddijrdmMOmb
         9+4msg9/FPXk+L/2oCrfVwx99bzfMC7uajuoOP7WIIfKyWEnSI98CFoETtOaQxN6GyA7
         NfrCHoZNBzRnPEdXY+CVMt/7DfjAM/YuqsstvDSEVA+6ws35y5CIycknh/x++0hDUPIk
         N0OqGpB6Anro187fWmC1wKDW2rbeydvZKb+BD4r8BSCrHwNvJlVST836M+ap/Lv5oFlJ
         l36QCrHn0nikaALPLUYblDOjAdOH7PJBVbN1baGE7vxxZPPxYij38YJenKP1044ibSyN
         +1PQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=viizbS8Fg5HieIAt4m4EQ/1i3HjeJortGPnrrtv4r8Y=;
        b=jo4pS4HBwlv6qUDG3+5TKF+5Z3H3vDK51u0UD76uRPtCdBxwT5Y00ABkUU/5eqnxOw
         LwAwwVID6Ey05ttSwtJk8ZMJm73Bn/+39QY2tGcq7qeo6ih5/vDsstHxJC8oZ8caZwpU
         ZgRewzLTYs4bfb9dJMy1+pRc9o6pGD1jKVNJUy41cGVU2Ak8UaVMgsO0eE9/ruoC1gil
         GoTGPWw20kkmNJv6aCok9WYEtzfQElJMr/ZR8Z5x8rzIy/epza6Snv6MSb2NpeczyEHG
         23gi/pY8sVC+u+yDTLhAD1mx0KZ5suEtdLwImC9nl6hGcqwCLCOC+Q0FPPIAoMGTosAd
         f1ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OK1kyUrg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=viizbS8Fg5HieIAt4m4EQ/1i3HjeJortGPnrrtv4r8Y=;
        b=LDgsDm3G/aoccX8xF6mevWuBLTK39zaZeayDz18VBublAi5zzeomyXHpQ47c5gmAUq
         vKoNs+RqLEq7vFXx14gNWDejXTWmnMm9qOtMJjhqPxxawV/X5ORzv2jZIyLDZHG2IvT0
         Lyfa6A4N1IsLlSO+pT+W31SCUC2m+jx8gYHWI70lmBDNQ7TyksShQAnxB8natWylCouw
         x4fOL5XVNhyWS6sCghOnp40nol+2s1jGKVuZYZNNKViKRpHR47gd2nP+ZsxyklOksA0G
         Kq0uf5kERJ9/dAJFJbLRA1wnROyiVEaeKPucnWyGytwytRF2TkFt2O4MO/0vv5iC0wt4
         +Hrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=viizbS8Fg5HieIAt4m4EQ/1i3HjeJortGPnrrtv4r8Y=;
        b=h9UgINxxwvrIZHQzqApNZvnj01S8dNET5Oz5W1AxteNjAVxXkZKV68c4OWMqq2kK4B
         Unckjj+OsdGtfWTY2+rCXZ9WLyv0OcJcwxgveA8ZOGD9HeE6BELCTkqD/ZNLW/Bj1yup
         jkMupVG+trAGoaTPv7imysQX5xB+6PhL0/ci5pdk+m2i20rX1UAw/CnlMO6pvR3jBJv+
         lDMSs1x68/WYL1ou2mddYs9xuLhN0JDkvVPaFyJ1GMLU3qY5JgfqECKHLiC7LgDUhDtR
         9tMKQ0+FqulFbKAScVvn+Zz3p+iRsH2JTwJzqmaHZhEy2HFPrAJdmrHKF1ubI91ViNwJ
         w9DA==
X-Gm-Message-State: ANhLgQ3S4zkwsw1X7Vs+1KkQJNZDHmt/814yTAiliaEDjENgj69foa47
	a+oJ6zenNQ9x1Ri6REM1CyY=
X-Google-Smtp-Source: ADFU+vs/ir2pv/7pHe3U0llTzQUjWC+i6T9ntp1MAS3sTaPTcHZ9yc9GPSkb5YV08Q1b9E0vLWA+YA==
X-Received: by 2002:a4a:3e90:: with SMTP id t138mr1759791oot.24.1585049582958;
        Tue, 24 Mar 2020 04:33:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3bc8:: with SMTP id k66ls964381otc.10.gmail; Tue, 24 Mar
 2020 04:33:02 -0700 (PDT)
X-Received: by 2002:a9d:7b4d:: with SMTP id f13mr22055866oto.216.1585049582641;
        Tue, 24 Mar 2020 04:33:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585049582; cv=none;
        d=google.com; s=arc-20160816;
        b=RywdCdTzZOct85U9hkxPZzh+Lj+jIEkoqZlSAmvETXAEbjcOPTSRtm/flrOAbiEF0R
         Z6BoytwNsxGnVU6tGzK/NvI/IDq/gmcWPssmRY58g9ly3wkDImwfQ+d//pbKPQDoJke/
         ltKmg4pYO5jQjlSGYtYe7/xth2Beb7V9vy2lZsNpkAp6BIhohDmdM/6ZV2o/UI4U7LjF
         dHbq8DnraRTtLD8VJLkFMLe/MXXWBNLyXxUj53leqMJK3ANBxvJK5dg0jZBeIy8T9khb
         gS2tvGQes7o2Y32fGT3pgVbzNMspuaXR8ZTEfjFzSMoX4x3VwHIkbwxZF/E7Y354cBB8
         a3Tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7Qc7uvYUanhBTdoYQFCXEMtsiSU/KMpNbflyVVa/k/0=;
        b=0mI38sQma1fiaDTnwuMvFobgdtUVN+nLlslsxf+ykrtBoHJ62jQwRkxolMpI+2//NG
         djPJL9n7DQeKqUk6HEfSKiwRkvnWxrprcfXYYKTiCpH0xU6H1yo6MGqndQ+2I0iLxw1G
         3NFd9ZEyQXm1OXqTYC+CpQwvrga7ke22sk89uFk94mWGFtED5O0j8fEBtuPSOedlFupR
         jtmCxFfX94GCCdp8h9FU/C6K0HYjWWLskOTgb61qp5YZPkUPQlopW56UXMgiRxRWeXwF
         x5aflhg0TK4mAj1xGazRisc4RpBiRm+477Ka5lkrxgJUAwqFi5TmEgOgKwDLOnaTA01t
         uKTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OK1kyUrg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id m19si297455otn.4.2020.03.24.04.33.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Mar 2020 04:33:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id i3so10740677qtv.8
        for <kasan-dev@googlegroups.com>; Tue, 24 Mar 2020 04:33:02 -0700 (PDT)
X-Received: by 2002:ac8:719a:: with SMTP id w26mr25506964qto.257.1585049581891;
 Tue, 24 Mar 2020 04:33:01 -0700 (PDT)
MIME-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com> <20200319164227.87419-2-trishalfonso@google.com>
In-Reply-To: <20200319164227.87419-2-trishalfonso@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 Mar 2020 12:32:50 +0100
Message-ID: <CACT4Y+bbVtwfYUC_v3V0ZBh2kVwp=PHKq6Jyqiz6BVbLTtL3bQ@mail.gmail.com>
Subject: Re: [RFC PATCH v2 1/3] Add KUnit Struct to Current Task
To: Patricia Alfonso <trishalfonso@google.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OK1kyUrg;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
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

On Thu, Mar 19, 2020 at 5:42 PM Patricia Alfonso
<trishalfonso@google.com> wrote:
>
> In order to integrate debugging tools like KASAN into the KUnit
> framework, add KUnit struct to the current task to keep track of the
> current KUnit test.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> ---
>  include/linux/sched.h | 4 ++++
>  1 file changed, 4 insertions(+)
>
> diff --git a/include/linux/sched.h b/include/linux/sched.h
> index 04278493bf15..1fbfa0634776 100644
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -1180,6 +1180,10 @@ struct task_struct {
>         unsigned int                    kasan_depth;
>  #endif
>
> +#if IS_BUILTIN(CONFIG_KUNIT)
> +       struct kunit                    *kunit_test;
> +#endif /* IS_BUILTIN(CONFIG_KUNIT) */
> +

Why can't this be used if KUNIT is built as a module?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbbVtwfYUC_v3V0ZBh2kVwp%3DPHKq6Jyqiz6BVbLTtL3bQ%40mail.gmail.com.
