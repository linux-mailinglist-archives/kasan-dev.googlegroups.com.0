Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFE6R33QKGQEDBYF3DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D93F1F7995
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 16:20:04 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id u1sf2748549lfu.10
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Jun 2020 07:20:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591971604; cv=pass;
        d=google.com; s=arc-20160816;
        b=w66Awx+nPXQm+xuhAKLkDucRjCJp5EJ9loyPrsvOSxRMAuuMzMMxJVcA/H/8pNdblb
         XmLV3mGZ301yOE1TB2PuJKGcPWXuNo2qWOAz2f9CNIFCYHd4MCx4mNxkmNtWCG7bANiU
         Ba2I4FzHlyU3nSVrBdVb4Q64t4uRNQJfx5U5hfkjcDk34o1HBDgewp3A3AmJGupm2U7h
         VHhft76gYg83fHVlZih6eLG2yQ0wnWN+GYZU3+nV7VTaqALnLoFGW0gQ89PDGj04BPs6
         9G6hcLHyUwUzopd867XiIH3pgmDtwQXM/Z2U+JT7S7yWs4QMZpmq8ZthjTJd7fZ2J3Ey
         pE1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=W0fvh7K8DqpLD7mHUyHih3E+Dw4k1+JGt833dgrI/x0=;
        b=siwEbI32jD7UsbzUu2nI84i7gc5o41S52BQEzrxuy3nShNlaacRdguJrykxiDqPMwr
         lZdXAIyHewz9mV5VEIJcGgUc8YN5FM6RUFSc4u5j1Eht9m2FN2zZ6dxFKCE+0fX0ycbT
         Z/WjKrVbeNe638geam2KFRl4MD/aFiQBSskyPI7rU/swc+5iJMAg9wfs8a5BZOvQ6gZI
         R4y9sXISxfutvIZdrDRRSt827fhxJxIpx1oGw2nQib8+0EXuA/neWpM6vayw14aBy6Co
         QnRfb07CvPXE9A742IYJh0f/ug9wEHd1/8M7dIgRwMH8aIYA2DIAe5sevl45i1HqHWLh
         Gm4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mqPlaGnn;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=W0fvh7K8DqpLD7mHUyHih3E+Dw4k1+JGt833dgrI/x0=;
        b=K7PQ8xjBJncE6bhnNumfml9+PSBzDatLmTkkIatFz12GAMank+90Nc1swO9ai5VbhZ
         jCcNLyIOqou5YsMEDCfvXAoXq0RCQLJH26VkYsFYJyXwxO8rUu3XducGFzUmGOeGfpao
         IHs3ZWhwzQ6tbVb9k+RsHHYbkqBsktaNp55Os3kOcYL8sbnH0TTpcq/K4rSC0+UGjJx/
         M/0FtK31CsIhZSJjlKk0BdRxjxtZ8u8WMpADSVpeGV7lHTJr9QeULIb1pjZ8ZQ80KOV/
         VaTPSZ9MKSVTuooTs5nIRASYPyQjlwOjEB2YYUBWyb3/uzhpu8mM2vzJsC9oRJfASAan
         yajA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=W0fvh7K8DqpLD7mHUyHih3E+Dw4k1+JGt833dgrI/x0=;
        b=PCmjtLfH8pYP5ZA37D39WnbAnn2dj3sSGOQ/oFjLeGbwgPiXG+Ue/2yyptOD+jlObF
         04D+HGPp498m263c6z17WePV5JrEN7rimiqaNrTTwP6z7TDD6TsZSW9y5hxxA/lzq5He
         Qi53tazbS8ydZL8hne9fFlac6nPm+5rh54CSAj22SEoOkaEEEORBOofuP6KXsYaGTDDe
         0MMU+7SxCI38Wr5qnExIJWqdLubQvSlWmwWpcn7pNpj58tIVwH/wtvaXGGWi2ax3xR/1
         Bb39TUBUn9jChwjQVWDBOCge1coeF/Us02JbCErIeyrNQYffbJfJL2TadVzadgtoCfzl
         A6Zw==
X-Gm-Message-State: AOAM530eNkO04rR00iSLGsLga1c6vOd8WIkgOmgWcIeJH16QKlIe/psJ
	TWkCEMQIbYefw8ERGf38g3s=
X-Google-Smtp-Source: ABdhPJx13x1Ay0x/N5d8xbF8k3eRcffA6+lZRVmCbQdL35pjSL7akTUylMmHVcmMFY9JM4++cHhNhw==
X-Received: by 2002:a2e:309:: with SMTP id 9mr7269686ljd.385.1591971604087;
        Fri, 12 Jun 2020 07:20:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b61c:: with SMTP id r28ls1244603ljn.5.gmail; Fri, 12 Jun
 2020 07:20:03 -0700 (PDT)
X-Received: by 2002:a05:651c:106c:: with SMTP id y12mr2122930ljm.427.1591971603341;
        Fri, 12 Jun 2020 07:20:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591971603; cv=none;
        d=google.com; s=arc-20160816;
        b=tMlpkzKqTc+L0XKjBlXcA+slDXWe39lAWQG4KiGfXAXiDiaZ2FPOoL/7gFqsEtHY7o
         Y8qv8N/HY3gzYz7e6OQtFkB/XuwPr4Fqwn6sEq5w8HxFU5BpCayM2l5L3CZgVz3570Kr
         hSX1rwSQ2QN7RO6dgYiNrxdhy4lkmcAFTorbrEctng9XTgvskXfBFUtkqRz614HxXwbX
         M2Dt60VXpoDL8sxZC58GDs17l7Vbgc0G6LcIkb6ttKDgqT7Uty1dAOB6kH7cGFc/J6TT
         f4pc6aB61X/A0vSiHWY1f+N5Eda0RnwW+Z+FiJuYJKcNYoFRdpiJYxb8p4Y9crP2TFQO
         eG1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5Jpp3xZtDoxpXVm6WWez85OGLnvKv7q+AwTyuIffLvI=;
        b=Jjca2xpUO3yl1duc/KfWFlg2y1Cl7sXo6dSaS0P1VX95NVI0JhYl/yJPDJCgEwEU77
         WaAUWiO77HzPjtIowboonpup4fvK/yfvEqfD3xAWosqbqFoBUq7c7ynW6hy6J6wsuKlG
         /R9ZCdhL7XkEUC/z4Dd2h2VhliMlaOiJ7x5SMHgShyzpvwPserYwJPhS+GyEq54PUkZs
         JPx+UVJnv2Nz0MXUlBez9+zDQtk773Qw3sicHisi8h77nnCxYpXqV0OZu6s+yNa8jOp/
         MiixMQe/46LyLcJOST3U0q6rOwpqrHN9j//Pd54bkbk033vf36UQm9/Wyj84EBgUdYcJ
         9aqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mqPlaGnn;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id j14si310456lji.8.2020.06.12.07.20.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Jun 2020 07:20:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id x13so9928942wrv.4
        for <kasan-dev@googlegroups.com>; Fri, 12 Jun 2020 07:20:03 -0700 (PDT)
X-Received: by 2002:adf:e908:: with SMTP id f8mr15150697wrm.184.1591971602573;
        Fri, 12 Jun 2020 07:20:02 -0700 (PDT)
Received: from google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id t189sm9016660wma.4.2020.06.12.07.20.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Jun 2020 07:20:01 -0700 (PDT)
Date: Fri, 12 Jun 2020 16:19:55 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jakub Jelinek <jakub@redhat.com>
Cc: gcc-patches@gcc.gnu.org, mliska@suse.cz, kasan-dev@googlegroups.com,
	dvyukov@google.com, bp@alien8.de
Subject: Re: [PATCH v2] tsan: Add param to disable func-entry-exit
 instrumentation
Message-ID: <20200612141955.GA251548@google.com>
References: <20200612140757.246773-1-elver@google.com>
 <20200612141138.GK8462@tucnak>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20200612141138.GK8462@tucnak>
User-Agent: Mutt/1.13.2 (2019-12-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mqPlaGnn;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 12 Jun 2020, Jakub Jelinek wrote:

> On Fri, Jun 12, 2020 at 04:07:57PM +0200, Marco Elver wrote:
> > gcc/ChangeLog:
> > 
> > 	* params.opt: Add --param=tsan-instrument-func-entry-exit=.
> > 	* tsan.c (instrument_gimple): Make return value if func entry
> > 	and exit should be instrumented dependent on param.
> > 
> > gcc/testsuite/ChangeLog:
> > 
> > 	* c-c++-common/tsan/func_entry_exit.c: New test.
> > 	* c-c++-common/tsan/func_entry_exit_disabled.c: New test.
> 
> Ok.

Thanks!

Somehow the commit message contained the old changelog entry, this is
the new one:

gcc/ChangeLog:

	* gimplify.c (gimplify_function_tree): Optimize and do not emit
	IFN_TSAN_FUNC_EXIT in a finally block if we do not need it.
	* params.opt: Add --param=tsan-instrument-func-entry-exit=.
	* tsan.c (instrument_memory_accesses): Make
	fentry_exit_instrument bool depend on new param.

gcc/testsuite/ChangeLog:

	* c-c++-common/tsan/func_entry_exit.c: New test.
	* c-c++-common/tsan/func_entry_exit_disabled.c: New test.


-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200612141955.GA251548%40google.com.
