Return-Path: <kasan-dev+bncBDDL3KWR4EBRBQHGU6BAMGQECDEINJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id AD4C1337029
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 11:38:57 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id gv10sf6654687pjb.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 02:38:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615459136; cv=pass;
        d=google.com; s=arc-20160816;
        b=ChGkyizt1RtrSh2LLaIeiqqPRDi6p88U+0sQivbXOHCUSBMd4mRACu2nFf2W5gYVzz
         YPK459yo3TiBle5qxjbgLzg7gc4yXzi3b7JdrRbi+5mBQpmMhO8iOU93+U4YH2pr1lJ3
         B/2R1xieENAn5yNp8GzcyKmDwt5GBHJFu87IBm+4yEidQOFxGW75+vyL1ZE+uGiVq+rF
         GSUGVFNNDXkN+prtu4YAJBpQvvfml/XudTI+snp7tgrM32bliQbb9lWKnWK7AVbVEnzY
         gCfDkhHsOFN9KpwdHd9U6uE3CJKkw8gpxL3uzL0W5l2Ffig0uOklzNtG5ssWCUk1bako
         qfgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=EnJcLhyLnsGPTixDOIqSm4rceM3I5AOMzknW0NYoN6I=;
        b=SQV3iYkI6W8/kBYbEVn8ghbbVMC9U/P7W0Z3cFbuBWwnBSeKN0AEs5jIHzULParzon
         nZ7QS4iXJw+SW4gzkxFuikBL4jGHy9ht7QysLp7YpNqpyeGdnTIZkdWvgKtP/mG1urgK
         I94RN875PRAUP8rq9tK0iNUrxaOaLnScEtQ3LpluMCoLleXv0hNJxQ6+NtbtwKhF0ZYK
         g9vf0JoiByLMlTnM4g5XfePatbO+zH72CCSgA4QpFY92Mk6Rw4mVdPM5s+R8soYONxR9
         ftP9kY0ajrmJOvgCYYYvujhFOoZhzJAHUh6kBrJ8Fjqt3Vz2oTBbBsdHD0L232ERtQpB
         VxJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EnJcLhyLnsGPTixDOIqSm4rceM3I5AOMzknW0NYoN6I=;
        b=eV6mhuA7oebFj/cDaCtKeMwSkqtNVdkJfw+NQYgZRrep2Xlsh/4cY4VRkNqsom+Lde
         yvYvYeiJ2qHIr1MHtYJJ+mEBRJQkqC1auVrXfsRlKtjm0v75nQ7xA27b3GSFgTEULCtr
         KxGdnMthET3kzNNoeyip9VvsZea1Cn0PHDg1yEXW7+TyWFMR0k0dF+GjtR+CoQOnK6lE
         ZpiQ2WJeuFUrWoflNtWaj38lWlm062OSObU/oz45I09JAxDZc1hAfl+/BoXVHIE8NuVi
         Ls5kRqqfD/vFebhERZFwq1da3+8KU+3viukxYuXYYgeepSWTu7P3wvyMQpD3jarlWVX8
         JD+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EnJcLhyLnsGPTixDOIqSm4rceM3I5AOMzknW0NYoN6I=;
        b=J4vI0XQBSunkS05+ZQ00vY4+9dhJS5G0t6842cbKPL2BZ2zcGrEUl6wghEEEunSEs4
         OozlDPqx7Y7nwE9Epag8EeFiyNPed7S57yYfscUrdJ7tSDb1vgjLMNYKoVoNdzlQ0dZj
         6zIY3qYsDGMxDMyUusPb587vMqqu/fl2A6HvoXgy22jimKnMRIWi7EkAo3oEr6xQO449
         OuLWCQ6UQ34dYzFzy+7D802xQRMkakWg5VtVN7933WlK+kZZ84ZjM8b+puMfWJEJCsGL
         a4ifuKFcmH+IEGW9x9P6Lo3O9areKk3+yMrn58I1467PoDlUCtiqCaX8OcqrH06RxGS7
         hpxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531CaevDvHUKHFar3w2szUpb6XnB+UMUe8G7FE/5t6lN5oSp3lwI
	9WS3t0z2kxdFHiLf52rW5ZI=
X-Google-Smtp-Source: ABdhPJxT2oaX/0wSDxbFQZMHlkOrH0W6dYhk4ckphELtuKmCht5vg6TzfRv5Ob8MRsmTc9rZKv+Q1A==
X-Received: by 2002:a62:928f:0:b029:1ef:2370:2600 with SMTP id o137-20020a62928f0000b02901ef23702600mr7285292pfd.9.1615459136168;
        Thu, 11 Mar 2021 02:38:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6bcb:: with SMTP id m11ls2937350plt.6.gmail; Thu, 11
 Mar 2021 02:38:55 -0800 (PST)
X-Received: by 2002:a17:902:bd87:b029:e6:4c27:e037 with SMTP id q7-20020a170902bd87b02900e64c27e037mr7507090pls.29.1615459135652;
        Thu, 11 Mar 2021 02:38:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615459135; cv=none;
        d=google.com; s=arc-20160816;
        b=lViCt+Kbc24ebVOjBMlrspir09BuU1FI205ZXkVWVKYd/KHWsZmHlI/hylJ4gqSwhY
         iilqMhPNo3JCXG3kjm5/nSyiURjuXxR+GL6RpMzP7DT9tz8S+2IGXECZWNAcanOqNrFA
         n4DAU3FXAWZLHTRCfesStXKHKvvi0ZwweP6A4o4Pabk8AAxxMnxUCUzHJkNvuQNXZyW/
         cIgr+NsKB9qv0rtC1BP4TKXPui+jczS0VIGy0fl2cdVPxtSkHKwvQbE9QZYaUjCHnr98
         zTvIS/nwTo6Zt0XfbpWxLzBpdXHGVBdMlYGMsxmsymy5lhq17tEGc4LyQ5WrTKxJIPt/
         /KJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=bZ916PcDOT/t5UJsHt+1wW75HP+2D1g4pWB2zGiMJu8=;
        b=rk6Km4K93hPkrZI3CBJT9gnoVdwa+CpRi/WdFzXoVbMxx2hxtuqmuqhvd28xkGmkQM
         ZrbP7pwcd9ZO3WRVxasg8ApwNhxAGhT/JfK49fDogXsYrLcy0qb3T2tAE2JTkbkTUQVK
         Ml6lw9Ub/tAgfxmmOZ7hxdTQHFLzg0DkhadW7twd1fnyw4JL111qusHUZd9Ct5MrWfwH
         KPMNWfAx6mixvRjdQpBX6vfY+NXz7lbs5xlGbabocqE1a9dDSX/GkwwysceNWOp/jXJW
         Lgw0o8KNP/OUX9bKsP75cqE5hxN33mJ0F6GLq04ALTK9yPvmdp5OOwA9StybBnKeiXvU
         CHzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j11si156984pgm.4.2021.03.11.02.38.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 Mar 2021 02:38:55 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id AF13664FBA;
	Thu, 11 Mar 2021 10:38:52 +0000 (UTC)
Date: Thu, 11 Mar 2021 10:38:49 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v14 3/8] arm64: mte: Drop arch_enable_tagging()
Message-ID: <20210311103848.GA30821@arm.com>
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
 <20210308161434.33424-4-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210308161434.33424-4-vincenzo.frascino@arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Mar 08, 2021 at 04:14:29PM +0000, Vincenzo Frascino wrote:
> arch_enable_tagging() was left in memory.h after the introduction of
> async mode to not break the bysectability of the KASAN KUNIT tests.
> 
> Remove the function now that KASAN has been fully converted.
> 
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210311103848.GA30821%40arm.com.
