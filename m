Return-Path: <kasan-dev+bncBCY6ZYHFGUIOZO4JUUDBUBBSOTWJM@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 390FD7454DF
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Jul 2023 07:34:38 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-403242da2fasf36777091cf.3
        for <lists+kasan-dev@lfdr.de>; Sun, 02 Jul 2023 22:34:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688362477; cv=pass;
        d=google.com; s=arc-20160816;
        b=kmNmjDHEHAllIzGavFvqnYrVFY6s8+Qvq+KG52bTV4wUdkWJmK1L0e3A1xYCA+XPAn
         ikRmS/trxofD11ggnnIiJu2YMKgvoLWfOD4WBeGJgS6JqPdh7cWabH8yM4byxR+18MF/
         wlOqSa+y/oJbK03QNBBULqk9S7/46sDI62KLd1H1rAiJauoh6qUa/kRuhdH/WJrfyQgK
         Kn1PINh2N6uC6nhxfetS+mY9tECXfRP/2+EDACdUgJcNMFqtvgFk4bZbTeDry7BpzyHw
         aVydujZJwHAAbkgoVVnuibCE9snqJ1PJ77EDbwftYcMCRir/rXQXXS18i5E0o7808vnG
         QR8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:date:message-id
         :subject:references:in-reply-to:cc:to:from:sender:dkim-signature;
        bh=NmfbMfKzqSxuL47YSiqeRXlD/VKIq4qwKC6lCHMYX5I=;
        fh=K54+6ya5mw1F8FNwGeScvw9pR/K+MFSCWJttmrhVkm0=;
        b=o2gIuJYakgKRYBBAphezHm//LwfGmlfRcmhBUyQ8aTcwTIFvj9/KwO2OiTJniP2rrZ
         2K4eUXoBu8vbxX5qxnomi4kUXlM9y1kDjfZ4vAr2RwEcdDimzHM7F81uPrAM0zbvucXQ
         OcjTpDXcb3FoWXEKgfMn222QksJ8wzD3R0SmuANbJSWqKJP5gFcGx206gvbBlQZeelLt
         xf39rZHu64YdrKUxb4tc6LOnLI4HMbXd+0U5oLYveG94fKjcZvgv7u23Ci6WvCaJobOg
         hrCcaGK1zxGY0KXnjs1rFTVsABH1p2lOYwxVfy99/jvhRq6L1fqn4AqxGuiha7VDqCYJ
         iVxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of michael@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=michael@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688362477; x=1690954477;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:date:message-id:subject:references
         :in-reply-to:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=NmfbMfKzqSxuL47YSiqeRXlD/VKIq4qwKC6lCHMYX5I=;
        b=k9zDk3jtQZ+SuXzS0lMfLnHHxKrAsGuq/kN1Fm1ehbKMhWPo6llA2D//sPztOFsNHq
         a9UEiRXcKAGuEBrxMVow+6rVMxNU6iHs3gqUGpjswfV+H/h6aKNT/zRZpBrCJxsjDIar
         8ZVOcls1i9eilqxZimkveVXHSL01kttUHoCRpNw6LuDXPiiTCO3nUJ7+HRUIYT/k9sKg
         Ftrg1nvtM6kOaQjl3BOVjERcBrIJJhq7auWxKdl5lHvkVCSkaPWwisur6IIDsXumxWtZ
         5kfC1/N+Cne5VKet2KmHsg7lAOF8Tvfv999hyag9zYxz7C216GTNgDPBptbaPj0HZ0+W
         Wrog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688362477; x=1690954477;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :date:message-id:subject:references:in-reply-to:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NmfbMfKzqSxuL47YSiqeRXlD/VKIq4qwKC6lCHMYX5I=;
        b=TIC6zLPx993t7FE4XildQzTXZtkzXZPzstIFYMCILLeADctJOc5Yx1EDr139+7POqA
         NvupDo/eGYVpm0iQ7wbP5T+b4cJYSIg82Qm2LvNRj1KdQn/Ak0O6febALJt8ctXXOpox
         iQTNmQEe1ouh81q4npKZ31snuidPNRTpN0YwHXrrpoIyyJ5SZEziafFl3FAb3Glmz6H5
         uxFc8VJmLXrScgVPDcLuGQla2NEQnUZbDCzRLkwZaTUOx7d9P0JnWOsLADdI9GVhug5U
         53OrQvqdBW42+hJIXFB19Nv1fg3Pd4G9+Eo/qbzeohyWEsRZnrMuFCp/lbkqouOK4Jg7
         PcZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbCZIwmzKDB/MrUctAKwegmGIm6vptFaLiZnQBkCvIgrk57/QQS
	csKwek3vQdUB6GK4pLEUDiQ=
X-Google-Smtp-Source: APBJJlETc+G25KSzCzr7WIBON+va0LOEBHrffqkTiVjtt7q5Qsk8B6U6Atx3EW4qnFMewVT02KqEAA==
X-Received: by 2002:ad4:4353:0:b0:632:2ac6:6657 with SMTP id q19-20020ad44353000000b006322ac66657mr9847207qvs.40.1688362476737;
        Sun, 02 Jul 2023 22:34:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ed23:0:b0:635:a666:753c with SMTP id u3-20020a0ced23000000b00635a666753cls4425412qvq.1.-pod-prod-05-us;
 Sun, 02 Jul 2023 22:34:36 -0700 (PDT)
X-Received: by 2002:ad4:41cb:0:b0:635:e113:a0fe with SMTP id a11-20020ad441cb000000b00635e113a0femr9364676qvq.26.1688362476067;
        Sun, 02 Jul 2023 22:34:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688362476; cv=none;
        d=google.com; s=arc-20160816;
        b=ZtMDbIQ6CLlpZnppnGzw5t7teKp2HO+DDtPQcSH5ddjYBethaudr0xRgAQiTdPs8WK
         bUsHIdD763Xnz70Vvv5bUEkF+O7NUVVrNsfBMMsI8nvD6RubMJau1rlKy7ut+wa+Vc/c
         aPJxfu6aFYpoVv7Quc0X5tDFPzJhI3trjV08bZtV95BmdIAxhYGOQ3rAUfSqPixwQ+PN
         rugV4bQlxZCzmgoDlBpsFjVcJyfnKB5vPzGiSDX8sAUh+SldhijcYIiu+kIU1fYfRQHG
         WwYIu1qzXVKOUZsJYRjLlHHpzXPvkF3lBtaaOO8eidgcMIeFP6TlbmKWhG86f4bErBKQ
         Pv9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:date:message-id:subject
         :references:in-reply-to:cc:to:from;
        bh=8MG+xQl0+NIyV0+t33oxVoPl+1ZX4KOqqZ+lg3OW3Z0=;
        fh=HQ3GPcoqjd8LhhktToeb8HBzFOlu1ltYi9ZP/GNdiBM=;
        b=PZSO3ihy1d6xvm/zEnKEI+9v60KJbpUomCParC+kA3k00AKjv0PVGzRZkwF9Sh4EJF
         tMQsV7yTAnYu/UNRDeSHo8YEQTLzv+4CgtuzYqjM2Mu+KvAV+eXrF822q9PQntamNYac
         UPP/YDSeNaQkwww0ZjiVTfnCVlNTQVWoowceym1ZGH4K6XMIoTygGkf7gvQGapZjaQax
         PzyBDxWTLPtpYDcTtS0zimFwzL+I1cwTz4aBVPkL7xm6UH2WH0su6ifMarz28wq1NThA
         qhXAu9drKlGRQcXUBgR5zaVxUQ2mO/NDiaucj8iKig+urmxvNR7C3U/k+KVVQrdsuz9+
         uRWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of michael@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=michael@ellerman.id.au
Received: from gandalf.ozlabs.org (gandalf.ozlabs.org. [150.107.74.76])
        by gmr-mx.google.com with ESMTPS id oo24-20020a056214451800b00635e5fb79acsi959301qvb.2.2023.07.02.22.34.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 02 Jul 2023 22:34:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of michael@ellerman.id.au designates 150.107.74.76 as permitted sender) client-ip=150.107.74.76;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4QvZP416rjz4wxm;
	Mon,  3 Jul 2023 15:34:32 +1000 (AEST)
From: Michael Ellerman <patch-notifications@ellerman.id.au>
To: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, Nicholas Piggin <npiggin@gmail.com>, Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org
In-Reply-To: <57834a703dfa5d6c27c9de0a01329059636e5ab7.1685080579.git.christophe.leroy@csgroup.eu>
References: <57834a703dfa5d6c27c9de0a01329059636e5ab7.1685080579.git.christophe.leroy@csgroup.eu>
Subject: Re: [PATCH] powerpc/kcsan: Properly instrument arch_spin_unlock()
Message-Id: <168836201884.50010.3433894878909493070.b4-ty@ellerman.id.au>
Date: Mon, 03 Jul 2023 15:26:58 +1000
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: michael@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of michael@ellerman.id.au designates 150.107.74.76 as
 permitted sender) smtp.mailfrom=michael@ellerman.id.au
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

On Fri, 26 May 2023 07:57:33 +0200, Christophe Leroy wrote:
> The following boottime error is encountered with SMP kernel:
> 
>   kcsan: improperly instrumented type=(0): arch_spin_unlock(&arch_spinlock)
>   kcsan: improperly instrumented type=(0): spin_unlock(&test_spinlock)
>   kcsan: improperly instrumented type=(KCSAN_ACCESS_WRITE): arch_spin_unlock(&arch_spinlock)
>   kcsan: improperly instrumented type=(KCSAN_ACCESS_WRITE): spin_unlock(&test_spinlock)
>   kcsan: improperly instrumented type=(KCSAN_ACCESS_WRITE | KCSAN_ACCESS_COMPOUND): arch_spin_unlock(&arch_spinlock)
>   kcsan: improperly instrumented type=(KCSAN_ACCESS_WRITE | KCSAN_ACCESS_COMPOUND): spin_unlock(&test_spinlock)
>   kcsan: selftest: test_barrier failed
>   kcsan: selftest: 2/3 tests passed
>   Kernel panic - not syncing: selftests failed
> 
> [...]

Applied to powerpc/next.

[1/1] powerpc/kcsan: Properly instrument arch_spin_unlock()
      https://git.kernel.org/powerpc/c/396f2b0106ff343c61f7ae221dc6ae300f807760

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/168836201884.50010.3433894878909493070.b4-ty%40ellerman.id.au.
