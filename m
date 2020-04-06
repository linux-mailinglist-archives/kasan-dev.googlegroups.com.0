Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBCXFVT2AKGQETJKTH7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D26B19F727
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Apr 2020 15:45:48 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id x1sf13057485pgb.14
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Apr 2020 06:45:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586180746; cv=pass;
        d=google.com; s=arc-20160816;
        b=QA4ZTKYnBPYeh4z6NDpAABBJORpa8plE6ff0ycoLxqL2XqsfwSpy3IO3eoWlEq0j/e
         dB993UKG6UJSiQk8YMDhG89PzmrVknOjHsSPmBRFhBURha00Yj9H37V3ziNJieS7TNMl
         6/+rqXivy6sFfrp8boe+nCmdzXrK1b4426eBurwJPtc3duuzE8EaGtvyGE2w/sPByQDQ
         +VUcpWhHw5B589xnix/JnaDikR+jqkU9V4CusZvq5M9ux5xxBKtK8/wsILYLpCyGYjqi
         tcbptFWvh+X3mNs+PfI1zwIRgPBRfTzXUm4l7lElibSPYHXaTX4Qs70CQWyhhhU/HKti
         A8EA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:sender:dkim-signature;
        bh=l6eWjGA326oYE2mdbNmvM+hMVntgare5X21+/KO37VQ=;
        b=rrdq/p+GBCZctQA/qr78im3gxrfoJDMqVTYHEjZ/AZ+Ta7IMwMC7whFQ1ZaxOX7llU
         RwzTwDKeZmncOWOaTPVfvxQNGLeijgX6o7No09hJizmBXjD3PXZ0LCVkc3VqGg+UL/iS
         9ikdRtK6pR6CeEqcc3cQHz972G3Bk39pEAGRSamB9BvK9Y+6SqRKIuCGvyH6/RtZxwbN
         DzZLdQEYheBDaWjLcu3cO/AaYUj24p5mMBRVSMVaeboEIs/g7XZVmQEUv+3oxfXn1mFu
         M1jj0HPDrX6VVrVWNPOmQYtuYtBAWQIDpIiutH4igx169nlNCoAWNmWQUwQ99l/PA+2q
         dVMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=cI+2uYi1;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:mime-version:subject:date:message-id:references:cc
         :in-reply-to:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l6eWjGA326oYE2mdbNmvM+hMVntgare5X21+/KO37VQ=;
        b=VQkERtVdbr6ifguoiVOrlOaIVkmgfI5uWJJyIkRIMGXRhbUZ5rn66l7yMM0e8uY5LQ
         20RwkFaUj0V7QijaSLOUgz+vZdz8NQbHJ0TOUKaRicAI25f9U4M1Yk+C4sq0cAIxIkIx
         SOUplivfn5mK4Xc8HG0l6eKhihMGczIKYTG0E06Gu7Py3bE11+2qyoNs9orphFHnBUCV
         29AFz/W1hR8ZtLEHogJe6MRbLrFVO+ahuMTyq4JtFq91zb5g+JMZ6l5zGVZ4T70se/7K
         p472gjs0y8Exjx2HHPeZ2teEMkA0IQa/4y6QPCrnG6sRGrMJvZMRFzQFmGMFcElQUnaR
         prCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:mime-version:subject:date:message-id
         :references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l6eWjGA326oYE2mdbNmvM+hMVntgare5X21+/KO37VQ=;
        b=iPwcnk0t0UH1UV3YS0etN7zSCFUwPIfL6rmY94F7uD7yShRXRIgl9OR3iZCssc6wBu
         X61s/aFI1Jv+BNc1YsFBpEglGE77xgEHEfYLOn/OxTkYWkpY0pAGWkuCb/1eiVh4w1qA
         Q6beplPq9vCrfWZCTXgwyLoqTpvU4cetCK+LRe/P86UfEuA0PCArP4x/JwPWMqzGyjvT
         sJDZj3/Q+GRIaiVjJppHywB4MZFW0f0mVT3AeJ6CBE8ephDXX/cPifppbQGXEnACliGn
         +V+BYiUHZtldQJA6n/gx8LmPdhkRl4fw2Cpzce51b8Y1hvSQShLOXhCRElrV8sI3r+GU
         EfCQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYqHoOnH2qdUsCk8kCbmqOmH2NaDndiEfJArd8r2U3H+qq036IV
	9ZykIn5GLLhhb0nOp+U8AIs=
X-Google-Smtp-Source: APiQypIwRquuLsERdWs6DNS/08nUS25a6r6pobvwJmd6AQq/nZT4/g49pcPfkhanNvL6UkQm7H3npg==
X-Received: by 2002:a17:90a:d3cf:: with SMTP id d15mr7558324pjw.134.1586180746575;
        Mon, 06 Apr 2020 06:45:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:245:: with SMTP id fz5ls14547497pjb.3.canary-gmail;
 Mon, 06 Apr 2020 06:45:46 -0700 (PDT)
X-Received: by 2002:a17:90a:be11:: with SMTP id a17mr27215635pjs.150.1586180746167;
        Mon, 06 Apr 2020 06:45:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586180746; cv=none;
        d=google.com; s=arc-20160816;
        b=fZt27zMGoJsvYfCTtZ5D9a4T6a0PyGo6ZJ8F7N9FMM7M12lFgdLpgXXXGnss9u47i4
         9fvn2KkKNyID2ru3AHaFIreUyeCyD9vAG7Sd1WMczhaGn5Scl0pF/P9F2ZHgBFUmvfIL
         KTV5IGg0yNBuj+ELxt5LMlW2sS06EJVOM229D4nv84riNd41Cf7Yto79HedGWJcgFYDO
         LlxyDb83AQT8fRoeEljzxjYaxyIP3Iv1/iBU5oyzlW0vGR3iti185jrcCndqMd3/MGzk
         0bV9BvrIXvnc/B14pFxL6UWIWfZXQuxtDj2wPXzQJ+CloL0PRXe6elcFTQEeGhfx28da
         l1KA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=4wY1rqBiu6VyguDiXD3Q35BlZEB49/SImy/GPIj/YvI=;
        b=wlNzUDrJ59YhfRenRmr4C41FPao75advBfQHzWh9QX+wcSdVBhYF6aXdEN829mMK7i
         r2AUr/lFioQXvpHNWj/sgN7D4DJopY9QbpQ3eM8jsHEHF4OngPw2eRI0/lIV+tKhkr4h
         HipBi/yPnDjsYQSUzTxAyxrT53gGcnwz0beA0z/ynK0pIGuaisM3KhCYk+dHdePzB5Pc
         jrV18DdgrANbos3ZNKvB8oexVt24pEocGNhmafwtp5KaGikM5IARAklbotcC/NUEFMUx
         En+suChBUQCrSpmeRh2pQrSH1ZyAQJjfz1g8QRpyss7AwBINtiTVoZQYIDiZHaL3bPjD
         jkXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=cI+2uYi1;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id u14si1873pjn.2.2020.04.06.06.45.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Apr 2020 06:45:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id q73so7505434qvq.2
        for <kasan-dev@googlegroups.com>; Mon, 06 Apr 2020 06:45:46 -0700 (PDT)
X-Received: by 2002:a0c:f7d0:: with SMTP id f16mr20916964qvo.206.1586180745725;
        Mon, 06 Apr 2020 06:45:45 -0700 (PDT)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id n92sm1676549qtd.68.2020.04.06.06.45.44
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Apr 2020 06:45:45 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH v3] kcsan: Add option for verbose reporting
Date: Mon, 6 Apr 2020 09:45:44 -0400
Message-Id: <67156109-7D79-45B7-8C09-E98D25069928@lca.pw>
References: <20200406133543.GB19865@paulmck-ThinkPad-P72>
Cc: Andrey Konovalov <andreyknvl@google.com>,
 Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>
In-Reply-To: <20200406133543.GB19865@paulmck-ThinkPad-P72>
To: paulmck@kernel.org
X-Mailer: iPhone Mail (17D50)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=cI+2uYi1;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Apr 6, 2020, at 9:35 AM, Paul E. McKenney <paulmck@kernel.org> wrote:
> 
> It goes back in in seven days, after -rc1 is released.  The fact that
> it was there last week was a mistake on my part, and I did eventually
> get my hand slapped for it.  ;-)
> 
> In the meantime, if it would help, I could group the KCSAN commits
> on top of those in -tip to allow you to get them with one "git pull"
> command.

Testing Linux-next for a week without that commit with KCSAN is a torture, so please do that if that is not much work. Otherwise, I could manually cherry-pick the commit myself after fixing all the offsets.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/67156109-7D79-45B7-8C09-E98D25069928%40lca.pw.
