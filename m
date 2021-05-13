Return-Path: <kasan-dev+bncBCMJ35XEQQGBBU4H6SCAMGQEPFIPWSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id E25A337F5D5
	for <lists+kasan-dev@lfdr.de>; Thu, 13 May 2021 12:47:48 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id l6-20020a3770060000b02902fa5329f2b4sf8660283qkc.18
        for <lists+kasan-dev@lfdr.de>; Thu, 13 May 2021 03:47:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620902867; cv=pass;
        d=google.com; s=arc-20160816;
        b=pdBIkZH8Jow6FxfOXhyBCxP+FkjYznyYVx9V0d58pinaYAqZaniX+u0phRiII56sCG
         SMbGbqYY9kX6xYMhnNQ6AJBiuhIWXXIJNkhhmljVuFp9MAynQj0uwvdHpshXlFzBHlz8
         DKukXG1lYvNPxccZhNcn8HUBdoCV8cbBKY3VTlgExbwZMrYCzepI1cUdD3ylzShgC2CY
         zKp5PhDSP5GtzibpQ7XMjG/ShxWm/5kfFFD2vv5rnMEzdoz1w+W8CjLMm+KGJqpqREB9
         OTSlbLo2UxhXAyp67ECaimBqTql80veghSZDANMy1CG0z4TFvzzD9HLQ2GSSlr4qZw8P
         L6ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature:dkim-signature;
        bh=9QBovBc8QE74ZdXvttiPYoxaNC2KvHQ+gAdPmSDgsnk=;
        b=g6UY/a6dvcnfuXFVm9XBUneHHLMmYrSJuJle9RpwqpLNwzlikdrwsJ557nA8xQbZzs
         TeMXLM8GLr4xeXf0pr7OeO+skFTW5FVA+LPGwh/LqYjp+8gkEOfSSkDrJTn6CLE+NY9y
         C7HDM5K9SMNlT1KHX34RUT5p4qShn9siuLsrRETFKc/+utb2Fspho67evMlk30ysVAkS
         qZXfNN8deTw2wqD/jjdJi3P1LMyuWqQHmdKhWzf0iDr/TKwpgOOQJYXwpsymDXE4q6gC
         HeEqWL6zUj4nRRxSMN4+aPHjlMNf5RGNlzkpRO23oWyJuWH5LCYeiDyL9lje0PzwBKGI
         nu8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="SCfZUxU/";
       spf=pass (google.com: domain of akiyks@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=akiyks@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9QBovBc8QE74ZdXvttiPYoxaNC2KvHQ+gAdPmSDgsnk=;
        b=Qk3KHz8w6p9ZwCRjnMO6LHvN5CsgGT3ycYTWWGDo3y/z9rvpwCsaU3zxUKdZSlB+Ea
         JtWYuqACTW4Xevb2mOq+3br3BNvR/iMkt/tYvvg4Xf0chOjrCT8aAaIWHTbik4Ea3TWo
         ICGsVAA5jiuwiYaXb5FQ1lXFKj9gSEN25hY7xHbVf6Kqjs+aI43f5CM7mc804pz51h76
         t0MfZHQ8oEuFF3Iz9e1xCWICJ2f51zy4xJFY3Wejpj30GtOTw6Rtq48GpdBCE9QlXbs/
         kl9c6rYAH5b0a2lYlLV/D3Qwr3xmDrMa8/VZESFxOtqmkBy7RW267Q5tWpYhd9ryb37l
         km1w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9QBovBc8QE74ZdXvttiPYoxaNC2KvHQ+gAdPmSDgsnk=;
        b=S0S8qHWdZxDOjtyjNYiovY3hLw7kHhFlyfoX5i01BOS5wrjvpUE6WiQKZcLSpVwLmK
         CILOjnlgYH5zMK3e7VxNXyT4t1SUdKu+LHq5rdRlpnHogiyeaW5OF03pfqcvUsT+Q7lN
         zeqgloJRcsTGPW8oIVXw/OqWS2Zno7O1rn5keavlNJkwqC9V6xyH7ZA3tGVYX/CavXlj
         lYqstzLlh7SdzCLRGWzqew0Bd7phB8bFO0mrbFa7nQzXCNp4cR3N+1CA39HA82ul9PZZ
         hz7JZIWa9/j9jb5JAdHpCK1FN6FGbL/4oI2RMwMXcTchivrblfgGab9sIETqUve6kwh/
         dZ3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9QBovBc8QE74ZdXvttiPYoxaNC2KvHQ+gAdPmSDgsnk=;
        b=aM6Z0L4bpc+0Eb0CtBb5J7UMofy2Dsnq6dPMLbzkcWd+K87xmVjra8RomWLY14qCMH
         4uxf3XBgV0SaWrQu0rZzbc0RaH2UW+cNKDtwaJ/tmG0pBh3jtSmHbm8NTPZYKFE9KeB8
         lTnfTcgOIlKT5qwzggHnh6h6gcNLw6C4E3SNnAcXN3oVZI9dDo5V7+M6dWKAVoaIzi03
         iXNMLN2NAHBMCo8asx3eSooN/xCq5cmoaonT26Y6nP3qtspSDxEdE/zB89W03RDTmMD+
         /wWrM1Eqm365sfHQo0ouI3mJAXpR5X7b9hi3h1SQCHVCja1V8st/5VUK8c2dG9PfVybj
         y0qA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5302mgrhRGnaa+KSaeToJIVOnJVLW0C/mk60+bk06DU9ebAScrFN
	AEMbJq6pKRfE+lYDVP4iSF0=
X-Google-Smtp-Source: ABdhPJxLntzytzVfChJ7VSK46mlfFt6FBJny9Bs7F3mmVZi1yFp0IaO0noRVXU6HkPG5SsGse30RfQ==
X-Received: by 2002:a0c:d80a:: with SMTP id h10mr39455709qvj.25.1620902867724;
        Thu, 13 May 2021 03:47:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9806:: with SMTP id a6ls3685033qke.9.gmail; Thu, 13 May
 2021 03:47:47 -0700 (PDT)
X-Received: by 2002:a37:aec6:: with SMTP id x189mr39016322qke.348.1620902867331;
        Thu, 13 May 2021 03:47:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620902867; cv=none;
        d=google.com; s=arc-20160816;
        b=KDMGNR75Bk3tGpNSvRbH/Ab/iTA5JSh+W6FuU786mWOmSB31KGrVVVFt+GIuwnVYzB
         UBMbIdC8GQcEUg/czlddEX710EGQLeFtTIkmK1B7Fxl/XLFAgyczRdb+jgcIwbSLG/r9
         Q6ZyQL3AHPmRriPmLjswX4JP5mvwKAwCUtv5SrjcnVSj07alDLrkbbtMHWpZ52JrLNnn
         HHlpkOBGIFFiPWgB+dZGVOMyN8kk45VR+T9/3A3CUFwOa2COQa59aiXk8UAeeulJgLGP
         +R3HX0Dy+UqLBcGQg8QN4RbEB8IcvpJXfjK5UlMDz20BgsK9ChTYnphS2wLWJAr7Ub7G
         PM3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=GIWNgKfERCd8ws3NEsOZmkaYsKxmmQTX5MnGldnYq+U=;
        b=HZGq6Vn42qCgIMSRyYG4HHBUmWHJ/Mvu52zAa8FWTb9NdpWspg0CfUpNW3laslbShh
         cP/T5+CFUeYYk+XKmIgT7qHoyN/EFmZp7NOBt+dWX+ppwg5OoNCpe6PoEk3kn9/6DSv4
         opH2DX2bHEQHxzFa6WF8xsBUkvyJ0kElGNMP9PvbQAelIjLTGF4jydIiMR+CYWTWEZ5A
         uEDjcVFVvpxFiq8ypxVrZBL7hCI3rGdiJutHSWbU1fVyVhsFjK27uKIjy9o2COHTHE6H
         LwQdx6SzuMm1S9OlS6jYD5PH41mAaGegMTm0x1MUjqj3mq3Uaq2pNgVBl6GFI7S7WDWh
         Igeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="SCfZUxU/";
       spf=pass (google.com: domain of akiyks@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=akiyks@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id q5si217039qke.0.2021.05.13.03.47.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 May 2021 03:47:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of akiyks@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id q2so21293191pfh.13
        for <kasan-dev@googlegroups.com>; Thu, 13 May 2021 03:47:47 -0700 (PDT)
X-Received: by 2002:a63:1c6:: with SMTP id 189mr30948951pgb.144.1620902867026;
        Thu, 13 May 2021 03:47:47 -0700 (PDT)
Received: from [192.168.11.2] (KD106167171201.ppp-bb.dion.ne.jp. [106.167.171.201])
        by smtp.gmail.com with ESMTPSA id q24sm2178996pjp.6.2021.05.13.03.47.44
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 May 2021 03:47:46 -0700 (PDT)
Subject: Re: [PATCH tip/core/rcu 01/10] kcsan: Add pointer to
 access-marking.txt to data_race() bullet
To: "Paul E. McKenney" <paulmck@kernel.org>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, kernel-team@fb.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
 dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
References: <20210511231149.GA2895263@paulmck-ThinkPad-P17-Gen-1>
 <20210511232401.2896217-1-paulmck@kernel.org>
From: Akira Yokosawa <akiyks@gmail.com>
Message-ID: <a1675b9f-5727-e767-f835-6ab9ff711ef3@gmail.com>
Date: Thu, 13 May 2021 19:47:41 +0900
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210511232401.2896217-1-paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: akiyks@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="SCfZUxU/";       spf=pass
 (google.com: domain of akiyks@gmail.com designates 2607:f8b0:4864:20::42e as
 permitted sender) smtp.mailfrom=akiyks@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi Paul,

On Tue, 11 May 2021 16:23:52 -0700, Paul E. McKenney wrote:
> This commit references tools/memory-model/Documentation/access-marking.txt
> in the bullet introducing data_race().  The access-marking.txt file
> gives advice on when data_race() should and should not be used.
> 
> Suggested-by: Akira Yokosawa <akiyks@gmail.com>
> Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> ---
>  Documentation/dev-tools/kcsan.rst | 4 +++-
>  1 file changed, 3 insertions(+), 1 deletion(-)
> 
> diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
> index d85ce238ace7..80894664a44c 100644
> --- a/Documentation/dev-tools/kcsan.rst
> +++ b/Documentation/dev-tools/kcsan.rst
> @@ -106,7 +106,9 @@ the below options are available:
>  
>  * KCSAN understands the ``data_race(expr)`` annotation, which tells KCSAN that
>    any data races due to accesses in ``expr`` should be ignored and resulting
> -  behaviour when encountering a data race is deemed safe.
> +  behaviour when encountering a data race is deemed safe.  Please see
> +  ``tools/memory-model/Documentation/access-marking.txt`` in the kernel source
> +  tree for more information.
>  
>  * Disabling data race detection for entire functions can be accomplished by
>    using the function attribute ``__no_kcsan``::
> 

I think this needs some adjustment for overall consistency.
A possible follow-up patch (relative to the change above) would look
like the following.

Thoughts?

        Thanks, Akira

-------8<--------
From: Akira Yokosawa <akiyks@gmail.com>
Subject: [PATCH] kcsan: Use URL link for pointing access-marking.txt

For consistency within kcsan.rst, use a URL link as the same as in
section "Data Races".

Signed-off-by: Akira Yokosawa <akiyks@gmail.com>
Cc: Paul E. McKenney <paulmck@kernel.org>
---
 Documentation/dev-tools/kcsan.rst | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index 80894664a44c..151f96b7fef0 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -107,8 +107,7 @@ the below options are available:
 * KCSAN understands the ``data_race(expr)`` annotation, which tells KCSAN that
   any data races due to accesses in ``expr`` should be ignored and resulting
   behaviour when encountering a data race is deemed safe.  Please see
-  ``tools/memory-model/Documentation/access-marking.txt`` in the kernel source
-  tree for more information.
+  `"Marking Shared-Memory Accesses" in the LKMM`_ for more information.
 
 * Disabling data race detection for entire functions can be accomplished by
   using the function attribute ``__no_kcsan``::
@@ -130,6 +129,8 @@ the below options are available:
 
     KCSAN_SANITIZE := n
 
+.. _"Marking Shared-Memory Accesses" in the LKMM: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/access-marking.txt
+
 Furthermore, it is possible to tell KCSAN to show or hide entire classes of
 data races, depending on preferences. These can be changed via the following
 Kconfig options:
-- 
2.17.1


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a1675b9f-5727-e767-f835-6ab9ff711ef3%40gmail.com.
