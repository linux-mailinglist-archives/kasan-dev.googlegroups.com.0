Return-Path: <kasan-dev+bncBDW2JDUY5AORBGEOYCNAMGQEJTOXMYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AB0A6048F1
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 16:18:02 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id e7-20020a9d7307000000b00661a1c93fadsf8221514otk.20
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 07:18:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666189081; cv=pass;
        d=google.com; s=arc-20160816;
        b=CG6Oz0QzBiX9lBAxeEYHygbBP7R56GLkmreaARGezkLknrMoJ9Fv0JnyjeC4U97rfF
         aFTn0YydzCAIyGy5Bb7AEzerfDtUfC86rwQkYsxczPHq1TRxqr+lNvnL5lqej5whsaTg
         sHclb9CnhRn1xMl62pfmxhfGB72u1llRdZ0v9AkFF9RxMCziPi2kRYPIaNQ9a6wjT63v
         qvt1EqSjtMEM43TlUyzFlgrKq6AsCwvGQ/5tABCEw3ME5JOmfnqQ8G7q/TC2/sZ6M7oc
         06bNA2NrzcFVyr7cBhNRisG5aRcEm15Ce21HAoJEbOD7FgODMXMMMDShpNg7VLMFKGE/
         tZuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=LEqvImhbz8Pas65xLjEWV2OvJBmL/OTHWTBgApVU3TM=;
        b=ePNciUTAGVsDzwHKGqRzT9mhrBye+0K16tRBNM6NGNpuCSNQQOcUVuTQtzCZlSA3RP
         a0gKDK+I2/LI6emzpcgCp2yFvyXH8xHHDHONuIw1osE57m0hrMShuhtXAK51vZPQGDLc
         lGaBkojUNv7piudZPGylWnQE5dU+U4F9yPAJL25Qif0RHs8EARKwQqyjvZoyRI7FQSS5
         n0Rs39dATpmrTZxEsFM/rnuQNMoU/be853tulryQ+6r0WFu0A3eUQiCjh8itB81Y5PC5
         7nKFnMryGxml+tgm6aiaR27EvGSp3CevGQbO0J3jpIokThFivEdQwwzuYRLurQKej+Oc
         +0Bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=orl3WtaD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LEqvImhbz8Pas65xLjEWV2OvJBmL/OTHWTBgApVU3TM=;
        b=E5zXZD43sF9IQo9z3wVljeD69BwZYAFsojmn0l3/tfETt7KgcOyOa0xoTkAa9FjOjm
         fqVV4B1Aq0ibt4icvGWwuiYq9zs5tF3MoO8IALetTG8Dukf9O/zz7IGG0T8w6D1/ibqW
         IOnCVQRML+9ylit8HzIWwveyf6slbSVDQaRGsTUSxFSr/uofe+YDz0LufJ64Z8HgC0Nb
         43oeDu1tr4wu5tlT57nIeJ8gEfGvLZcYgZEkcvCpLUz0qYWHaUOJkWB33eZwJGdSFeOH
         j7Cw81ylqyDcXBngNCtvfgETwWqTPVmf7hIJM9X/8L7SziIKvfE27bqB4a4x3Rt8Y+KC
         xN1A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=LEqvImhbz8Pas65xLjEWV2OvJBmL/OTHWTBgApVU3TM=;
        b=fJuMi2L2OFxL8rCOk8YxvH7kDRyCD2wPEX4ouIkwLLtD7dcBoaXnzssahocIgXASNe
         fWWya1pB8+g30vEaVpQHAw/AMW2M9tVmJpsr0nDWKfjWaVU2x8HdNH2+zypbqJ6PDQBH
         Q9FMpkirQZ05OH4E5BVADL4W1gG4Nt+rTpw0lLBIsch/ED1jVRq6Yje6fWFsSbz2/F/D
         aNef3KoVPTv3yZiAi6QEf70tW4LAdqMbkpViZrdKiUyeH9472dUorZatQkLrsSkq9FNN
         Xhja8sOvRE8FNWmbNIZ2yrnYyBd0j9fvF7aFnoZ5J1e+yu11DzYVyII1R6VZKRJSRgfq
         NCLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LEqvImhbz8Pas65xLjEWV2OvJBmL/OTHWTBgApVU3TM=;
        b=FygeoGKEBCWkEMhwtKQZMDuz58RScsxdAkREKyYGNtNRgLLiHM0GfjBo5UR1ZKHAvK
         BYekOXFHr1SsOawLyJXLq1obekSHECr6qkdvmH1Jt8bEDG5rt+4niRu5g9f6Vup/+FQr
         katB7A7U7SxVvaNdZwG4daimA8RrkzW4pfxbuJN9hfesLaK/ApXyHIg4AxmyksGXTYRk
         jiGeaBu+y0M9W3VsKDooVw4BeYqbsmOeTyuCJ51h+K7U0Tqtqa7/OviejHOueYHbxsk7
         G9cnm0C4Hct84WKwZByONevr74DLHPYG+uV38E2bKPJUBH8HWHf3eXTP50pSXaJt8Z6V
         aj3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf34fUXjOVTS1jt/WuqyAPekO+2lJIVXLvvlEuX+RUNCvcsC5g8R
	rFEkp6Pc4VhQ1j7ASnnyYBQ=
X-Google-Smtp-Source: AMsMyM7g7HqupdQ4b+ObhDiOhDzrmiEW4OpqzhtEkdsoT/MAAYKyLCUN8fFzUkvEzEsPKzlniXFmUQ==
X-Received: by 2002:a05:6870:2487:b0:131:4fee:7c0c with SMTP id s7-20020a056870248700b001314fee7c0cmr4983348oaq.71.1666189080965;
        Wed, 19 Oct 2022 07:18:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:7305:b0:131:8003:bdff with SMTP id
 q5-20020a056870730500b001318003bdffls5841278oal.3.-pod-prod-gmail; Wed, 19
 Oct 2022 07:18:00 -0700 (PDT)
X-Received: by 2002:a05:6870:f281:b0:132:62a5:a5a5 with SMTP id u1-20020a056870f28100b0013262a5a5a5mr5125720oap.63.1666189080552;
        Wed, 19 Oct 2022 07:18:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666189080; cv=none;
        d=google.com; s=arc-20160816;
        b=ko4EOSN07mud4vbDRBh9F7/3HOFtNcknJS4Wiv9FN9jgCeYHZpNzMoajhmlhMgNIzM
         lAQ4aXbkUrXe3ml59A2qdAmosy8CD+mSHHkFq7PiEY6p6AMUcHZ4eKAhB5TYD3tXlT9n
         SGO/qB0MSH5KBzTTH1qtiROEINQx9kBMoqy7mOjoXS+am84HEdJFJpjSGr9Pxw4xLzEJ
         U/P4TlMfRrmeOOhnOaawiIdd7psklSwXhibTCyR9PA1FThxw6QxBf6sslhh5OtTHTIiS
         EE6Sqdwtc5TytXUbb9c7FKv4VNOuK2d8slTL8vs1qectUrXmPHtY6O+guhWhDqdvlfn+
         Tx5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cknIal1Dqn0NuUAETBIEQ0lkMDHrEUKWbBRZZcSw1O0=;
        b=MdMVU0zNkM/dUL0Ty7kva1njm/VtTdbvCimJCZm0pYAdNkFSaWney5wkMstmlAM3x8
         s+HW4mfaD9m7R6KC/i/LCnrt+sl6/FMHvkXXE41jsOTz7HuCv5sFxKuBJCk4EJXs7Fe4
         Es3zkphRaypO1HVAc0dx++pGJRHme7Z5El1bQewqiOXioCnTDds4AlxqRL5K3zWkoJ/V
         dm+eS0QjRt4bWm6kS7+kuaGmcs1CCGXzdNkrz2fQh61k1pkxliJliLg0jKruzLPmF9h/
         36PQJH9aWB35qaY1iiIhDeTDicauIe8TuFgwqQDeXUL9WF5DGMFyMau3zVNfzpNNnVJb
         MKWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=orl3WtaD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x72b.google.com (mail-qk1-x72b.google.com. [2607:f8b0:4864:20::72b])
        by gmr-mx.google.com with ESMTPS id fo26-20020a0568709a1a00b0013674fbe780si919950oab.4.2022.10.19.07.18.00
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Oct 2022 07:18:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72b as permitted sender) client-ip=2607:f8b0:4864:20::72b;
Received: by mail-qk1-x72b.google.com with SMTP id x13so10741116qkg.11;
        Wed, 19 Oct 2022 07:18:00 -0700 (PDT)
X-Received: by 2002:a37:b2c5:0:b0:6df:f8d6:6ea0 with SMTP id
 b188-20020a37b2c5000000b006dff8d66ea0mr5676134qkf.386.1666189080171; Wed, 19
 Oct 2022 07:18:00 -0700 (PDT)
MIME-Version: 1.0
References: <20221019085747.3810920-1-davidgow@google.com>
In-Reply-To: <20221019085747.3810920-1-davidgow@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 19 Oct 2022 16:17:49 +0200
Message-ID: <CA+fCnZdPwjThjY7fd7vBkMzS1eFXySR2AKrDK8weJ3p25fzS3g@mail.gmail.com>
Subject: Re: [PATCH] kasan: Enable KUnit integration whenever CONFIG_KUNIT is enabled
To: David Gow <davidgow@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Daniel Latypov <dlatypov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=orl3WtaD;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::72b
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

On Wed, Oct 19, 2022 at 10:58 AM 'David Gow' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Enable the KASAN/KUnit integration even when the KASAN tests are
> disabled, as it's useful for testing other things under KASAN.
> Essentially, this reverts commit 49d9977ac909 ("kasan: check CONFIG_KASAN_KUNIT_TEST instead of CONFIG_KUNIT").
>
> To mitigate the performance impact slightly, add a likely() to the check
> for a currently running test.
>
> There's more we can do for performance if/when it becomes more of a
> problem, such as only enabling the "expect a KASAN failure" support wif
> the KASAN tests are enabled, or putting the whole thing behind a "kunit
> tests are running" static branch (which I do plan to do eventually).
>
> Fixes: 49d9977ac909 ("kasan: check CONFIG_KASAN_KUNIT_TEST instead of CONFIG_KUNIT")
> Signed-off-by: David Gow <davidgow@google.com>
> ---
>
> Basically, hiding the KASAN/KUnit integration broke being able to just
> pass --kconfig_add CONFIG_KASAN=y to kunit_tool to enable KASAN
> integration. We didn't notice this, because usually
> CONFIG_KUNIT_ALL_TESTS is enabled, which in turn enables
> CONFIG_KASAN_KUNIT_TEST. However, using a separate .kunitconfig might
> result in failures being missed.
>
> Take, for example:
> ./tools/testing/kunit/kunit.py run --kconfig_add CONFIG_KASAN=y \
>         --kunitconfig drivers/gpu/drm/tests
>
> This should run the drm tests with KASAN enabled, but even if there's a
> KASAN failure (such as the one fixed by [1]), kunit_tool will report
> success.

Hi David,

How does KUnit detect a KASAN failure for other tests than the KASAN
ones? I thought this was only implemented for KASAN tests. At least, I
don't see any code querying kunit_kasan_status outside of KASAN tests.

I'm currently switching KASAN tests from using KUnit resources to
console tracepoints [1], and those patches will be in conflict with
yours.

Thanks!

[1] https://lore.kernel.org/linux-mm/ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdPwjThjY7fd7vBkMzS1eFXySR2AKrDK8weJ3p25fzS3g%40mail.gmail.com.
