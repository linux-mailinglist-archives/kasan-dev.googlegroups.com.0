Return-Path: <kasan-dev+bncBCF5XGNWYQBRBV5TQOXAMGQEOZXNK7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 7D291849AEA
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 13:51:37 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1d3d9d2d97bsf5489325ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 04:51:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707137496; cv=pass;
        d=google.com; s=arc-20160816;
        b=YKI+dQq3gkxTGeeAHwZTGulf11G0Lb/WYk4Og31G7KsxFDO119fw4zfhb5P+yieV+q
         PsUcC+MwBlK/EoyQRI2DwQkOV9tOjWJuHToGevZUXaUI3Zsw/K10faakD6i5o/nzdhdH
         y5U9kXMMyHP3aDoKR2MSErkgc0Tlp6XZ9nsNxt2AFQAQ1lO/5Dn6PgNB+DALdBq0cdIN
         v/ZCHpsF0QzCYFJtROBp6/Lhek49midjFMy6vdWd7qZSTXf2rZYTuIetybMdqbIA43NP
         x8m4co4wdDNaJiF8ta6iMDJ6GrY2m7twDLpzX5hfY8M/HeF/FKWNvoLNkDyh/WHVA2RQ
         BRWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=azxG/FwzMOKCmMZCvHmFXv8tYs0aJdf/+igt8DDHWTA=;
        fh=ZmEQAZbJK2umnKDEpdpQMyPZS8hSVyURDktfTce5xgs=;
        b=vpc9noU77YK76I8HZJmJiIkownIsplRkAmgLmVC/7AMgJd/eZLJ4adM4pYmHmRtqXQ
         FUtkVZQobgfOgXEERRk9vpj0l6b6z0HZEFbKXhTz1W77ZQv1Lv5onCoJ/VTcyNaVFy9s
         fn2RQanl4jQ9EDiaLd3zxWqRD5u5+X9/emFfRoJDdQULoOP9yOaGEY9C/Kfbvi0cwW8E
         YDCuEWeg7CcTeg9VxcvW/Uk5+ywY4j8TPc33gWlIr4TEKr60F0vWbfjHSXLb2VpCCT/n
         DMWOlz8mXLIuygyrgUN12bf8xWtzu/9fSQQBgWLHJhpPxEJgzuWT8ZB07o/AvmCGeWHK
         GcVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="E2y/QZzf";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707137496; x=1707742296; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=azxG/FwzMOKCmMZCvHmFXv8tYs0aJdf/+igt8DDHWTA=;
        b=k/g+rR8j2NyYygYv99osOVzpAYKScMy2Ql6tB5PikpTLiIK+EP0bFYMjn8DFGmqlQU
         HYeb/z2YIw+jiz2IyOWqNO+rclzITuU2Aa4b8HYs5SYRQm1sGv9bkqxbEERlS6OKvzry
         MbjY6Cr4wwgvPTlrcAlKfU2ulHwdXj0Cp33JA3h+OnGsS5+jr3pkKcMlsT33mu83tcx6
         e6EzxpD9s/HWNtLv85eRVHZy3M4ICegKiKK8+ELcMIY1r1AHmhJJUU/0sCXuc3DFHvd9
         cu6FQPrfX4VbUxULGg6ooc7+WhUj3JQ115A2dBPg4KE6fptnZWO+losGNd26dqKHcPya
         11Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707137496; x=1707742296;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=azxG/FwzMOKCmMZCvHmFXv8tYs0aJdf/+igt8DDHWTA=;
        b=NS8d1mDJG4bfLrL88BkBot58/VkTAPEqEUAkDV3/Luvoh9oMUeCHUPkSBd0TVPgVkh
         exQmw/ABgDQeHNN2WhPK0/iPXZDOa7wfwRWSdHoEy+ACtYRZBBMnVtGBzD1zq+NxWVgk
         iuVYpRzf3n02hfjBC415caU8cd/pBKRYnx/7dvJDXuddrBn/rU5yln6JZwAk0qyixLEB
         d4sI+SmU4fzOs3GA46yDSAQP9YkV8G9UdfPT1hrr1htGNbHT/CCdC2bYS5mc925+7Qiq
         CGhV1znMQdSc73C0qmKDU8OpMWVEl5hYHpVNIGBBQ75k7U57ebK0sMY0QsaBFxS8CIlo
         9uIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyi53iqYHgBC2WJ0sW5FQLmSyRzYMZ/BVswdC20wJrlGEvSc17F
	HrRzPT3pty+iRanBNOq5gawMAr70wf6z5pnbOlrGufx5SvHtX11N
X-Google-Smtp-Source: AGHT+IGKxeCWPhjGhmcU5y57drgBO9ffRnk97H95qKPICjVRIpXzDDE2IomEmt4U8sLCh8c62HC5Iw==
X-Received: by 2002:a17:903:2342:b0:1d8:eac9:bbfc with SMTP id c2-20020a170903234200b001d8eac9bbfcmr293834plh.15.1707137495776;
        Mon, 05 Feb 2024 04:51:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ea10:b0:1d9:c8bb:281a with SMTP id
 s16-20020a170902ea1000b001d9c8bb281als270439plg.1.-pod-prod-00-us; Mon, 05
 Feb 2024 04:51:34 -0800 (PST)
X-Received: by 2002:a17:902:e801:b0:1d9:8769:ad91 with SMTP id u1-20020a170902e80100b001d98769ad91mr7956478plg.6.1707137494665;
        Mon, 05 Feb 2024 04:51:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707137494; cv=none;
        d=google.com; s=arc-20160816;
        b=DMXz5QmMug+lfrbwjKbTjvN2PIJWp+fSoWGqTeRLWiVh7N+q06cbvJi/sITEfDYZo2
         Y+iOcZQLmh24Gypkwyz9rfDmYOg0tO+1m5H3VDo5lyslqS16fG+Zm5ZgngdasGmhQo92
         ZLISHkToE9TCLs+leE8WqJAzm75cqpEq9vAQm2q3pbVb5JjErqC3W9Laxd21MXWamRY8
         ElYBd0YQNfrR7ErjBf3aIDVoy9M1RlrILAmSeVLIGgUtMPxt7wYanJv9Et7jv8w30RQJ
         HIwOPrH1+JFs33yn4qYUcYAFSF5pGzUCbK50oBr1ustnnsD2QQ/UzJrpUuAyzyesV7Am
         71iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=lAuOEn9XClUdiH1Uvm7Me/u+LDru9Z+XedI9uQ/DMIg=;
        fh=ZmEQAZbJK2umnKDEpdpQMyPZS8hSVyURDktfTce5xgs=;
        b=blxGWxIKC5c1QYPpNUjVVzn5oBB1w9Mr3vu2Sx5tbYamr1nanC4FVrsckAdefejzPp
         pt/uIv09z1INS0iGYr7wFLm0/vmE7djKvZWXy2IRNVcTAntNEhBM7EymZnRK2+WSKmAf
         FC0k7B6o4oj6NVKYVxtZ0ehPkQruTJvtpvw1aBM6bgV3tIfk4g5eaQd/3wrbpYXdpCv8
         K9WfVRM70lprJ3G6FqD+aXJpjGNy8XCGqmGDY9YovX6Q9tfs/sKiPq54KBSBIcQqBBZF
         otj7YeQb3Vl7grP4KZFd/GtchIT7LwRnzbz4ST05x44Ml2X8fAU2lgzK8ypPr11fJO4A
         2MwQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="E2y/QZzf";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=0; AJvYcCV9kaiWHaO8bFvTd+R7L0NrNrhYOb3yv/e08C3+u+bZxu5L8FYBoGNcUs9hMTRQpZXOgeCW4dZNK3vxRCYBchE/mcJOF/ZBLy2lRw==
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id g12-20020a170902e38c00b001d974ffa202si416842ple.8.2024.02.05.04.51.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Feb 2024 04:51:34 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id d9443c01a7336-1d93b525959so35191435ad.0
        for <kasan-dev@googlegroups.com>; Mon, 05 Feb 2024 04:51:34 -0800 (PST)
X-Received: by 2002:a17:90b:2348:b0:296:a76a:9711 with SMTP id ms8-20020a17090b234800b00296a76a9711mr1937769pjb.12.1707137494324;
        Mon, 05 Feb 2024 04:51:34 -0800 (PST)
X-Forwarded-Encrypted: i=0; AJvYcCXiDr027h34JyAnnlbBVWpPAWDZpuzcJBvVg61uZLSfkey6Ga3gEO4vzW8geoynvMjRpmilnd/TWS78wZJw+96i9pzUQCwSmpSuqHwoEo15tfbU6rcH7UVYklps9ooOyytmuS/xlI90immDWeyq3Fk9hFAGcYT/u2M1DCBv/kw+sMnnos/w097tCKBAZ1LRPFxNqM7uFMHakgxwdr8WwHez1xPq4lFRJjmqmD6dsgDdrV6qN8jpYIFJmnx7jmLo+WVJD8RevM3IWaISVxLWL4mz9/UQvoXn4cCSIMd1A6YgbgIvRSzOjKJB9GwyuGGjPG3Uq78Q7dWJ4ayOL44pmn4+p0vUy5m0jsc5lwVI3FenW4mxHFJ8G3B7xCyKFxLCIiHu7Z8ofnm6GZzHx73zVNasMLQ1UcALy/hVwVC8XUAYrHEulzG/h3e2dbt40BZqg2+REzKS9LJYKqKHVth6+Wayw073kKyFGoYFddC6lmaYEFr7/NnjAdouop2NLJ8J9yKNv0KrghI=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id nm23-20020a17090b19d700b0029464b5fcdbsm5049540pjb.42.2024.02.05.04.51.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Feb 2024 04:51:33 -0800 (PST)
Date: Mon, 5 Feb 2024 04:51:33 -0800
From: Kees Cook <keescook@chromium.org>
To: Marco Elver <elver@google.com>
Cc: Justin Stitt <justinstitt@google.com>, Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>, Hao Luo <haoluo@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nicolas Schier <nicolas@fjasle.eu>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Przemek Kitszel <przemyslaw.kitszel@intel.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org
Subject: Re: [PATCH v3] ubsan: Reintroduce signed overflow sanitizer
Message-ID: <202402050448.0FB78C7C@keescook>
References: <20240205093725.make.582-kees@kernel.org>
 <CANpmjNO0QOsHQOqDf_87uXFB0a=p6BW+=zF_ypb5K0FbaObvzA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNO0QOsHQOqDf_87uXFB0a=p6BW+=zF_ypb5K0FbaObvzA@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="E2y/QZzf";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62d
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Mon, Feb 05, 2024 at 12:29:21PM +0100, Marco Elver wrote:
> On Mon, 5 Feb 2024 at 10:37, Kees Cook <keescook@chromium.org> wrote:
> >
> > In order to mitigate unexpected signed wrap-around[1], bring back the
> > signed integer overflow sanitizer. It was removed in commit 6aaa31aeb9cf
> > ("ubsan: remove overflow checks") because it was effectively a no-op
> > when combined with -fno-strict-overflow (which correctly changes signed
> > overflow from being "undefined" to being explicitly "wrap around").
> >
> > Compilers are adjusting their sanitizers to trap wrap-around and to
> > detecting common code patterns that should not be instrumented
> > (e.g. "var + offset < var"). Prepare for this and explicitly rename
> > the option from "OVERFLOW" to "WRAP".
> >
> > To annotate intentional wrap-around arithmetic, the add/sub/mul_wrap()
> > helpers can be used for individual statements. At the function level,
> > the __signed_wrap attribute can be used to mark an entire function as
> > expecting its signed arithmetic to wrap around. For a single object file
> > the Makefile can use "UBSAN_WRAP_SIGNED_target.o := n" to mark it as
> > wrapping, and for an entire directory, "UBSAN_WRAP_SIGNED := n" can be
> > used.
> >
> > Additionally keep these disabled under CONFIG_COMPILE_TEST for now.
> >
> > Link: https://github.com/KSPP/linux/issues/26 [1]
> > Cc: Justin Stitt <justinstitt@google.com>
> > Cc: Marco Elver <elver@google.com>
> > Cc: Miguel Ojeda <ojeda@kernel.org>
> > Cc: Nathan Chancellor <nathan@kernel.org>
> > Cc: Peter Zijlstra <peterz@infradead.org>
> > Cc: Hao Luo <haoluo@google.com>
> > Signed-off-by: Kees Cook <keescook@chromium.org>
> 
> Looks good.
> 
> Reviewed-by: Marco Elver <elver@google.com>

Thanks!

> And just to double check, you don't think we need 'depends on EXPERT'
> (or DEBUG_KERNEL) to keep the noise down initially?

Not for signed, no. It's almost a no-op like this. Once Clang and GCC
support the wrap version (which will likely require changing the
command line argument), we can re-evaluate. So far in my testing, I've
not been able to trip it. I'm planning to get a local syzbot running
with the wrap sanitizer later this week to see how noisy it gets (if at
all).

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402050448.0FB78C7C%40keescook.
