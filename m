Return-Path: <kasan-dev+bncBCF5XGNWYQBRBMGUUOFQMGQEMWYBKWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 146ED42E6B6
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Oct 2021 04:40:51 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id m9-20020a17090ade09b029017903cc8d6csf6371520pjv.4
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Oct 2021 19:40:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634265649; cv=pass;
        d=google.com; s=arc-20160816;
        b=gWbd/i8LnK/j7htSyHdVio435LmWiJe9xQSFWqN6hmX6gP0yygUT7PRlDO8Kl+0wGv
         +8fb5qm5vkyqhKlwQqEeN1IuKIGSNN6IGpKj8QcFnLWiqud+tYoilNw/SGXFk2m0WI1p
         aP4C0twfe/xzaDqZlaRb+hCTWzkcF4SEEro2TbGMYObOA3ovrlFfT821RY7yg5rl0RHL
         n0+LCbIIfpU9YoVpGsmQVLO+ABLKgUifla5V7bI4b43LGM5e/KBEdNUGL+XZxp+M3zDx
         YsmSs1UQsTWdnlF9DlFqecmg16e2QkfKa3JhmCbW3DZEr5Zrp2X+gLgGmTeHVqfYkbSf
         oZCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=c/YyXk3sDQqus7YJiokI1ZeDgufqkGNzGPjo+5t3+BI=;
        b=JLb9JLAU9rP1U7KQJhNZ7Um1Ij2EaQ38K9dkBAWKW5xoHGFJObYlMgwM7sOwcQe5Ax
         cezJsuE1hdEYIJkWcn+zgGPUIBv8F3chld5/33OOjK1k7J0tMln4wHZk57dYKeUbysCf
         taAleZ5BzzxnweiOzrGMxLE0VlJlzyfHQnTd+bAwCdy82wNgi+Fiu0QtXPMATZKEAzYq
         MWFlX9oN0YoW3inbmaehjzy3Y9Q04lTdalTB+HYSxFDGDhNamHUIdGHbdcljeJA/XEYw
         DywDKn5yzDGjlWRiCxEH6sY4qTImKaUccelNzWP4J0K0demN42HGjOoB/9LvwgvAZFVy
         9TdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=EvQpgtaA;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:user-agent:in-reply-to:references
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=c/YyXk3sDQqus7YJiokI1ZeDgufqkGNzGPjo+5t3+BI=;
        b=aA1uiNSmOJJAwC9ZkerRUwJk3vL3R2rHSiyTd20x9WzDjG+KZGV5kaH1ZOrbqdmUhP
         5KfV5Ixn6Iq+Bz5NjLvOrWtuLjPNaCI+A70IpDjqjKMR11ch7aA1ml8YV48PgqNESAD+
         dpeUvGFwmki96eaHxSMBS7ZRTfa7rC5qV5BTk9zBTVkYPxE3TpHqujvjQ8ElArULwJIq
         7+8/4wLZ/kh/PyjbvXaSpmOt9vAHhuPIX9pePj21MMPSP4mAExllrNRNdwxRv0fn+ZUb
         enEzUpEucjj8CgbJazpNzHVvtdrhDATnytHmsUklyqkFYbdvbvAcRhsgZDEttLUkLnwr
         mgKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:user-agent
         :in-reply-to:references:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c/YyXk3sDQqus7YJiokI1ZeDgufqkGNzGPjo+5t3+BI=;
        b=5IWRzvRp48+SI/ZcQrOBeYt1EhJKxdjXjrdhhmRLzmXnuLhGyjy7fwB78/uCalVpmk
         690ZH/VBto34u0OPeP0WCzrf8gTPJPtJ1QMQ3dDMMMHOBl5PSt85Mi6Lv1DTfAGzxEZA
         wGJ0YqHWS0PJnii1/ND10x25WjKqhxE3Tgu6sqqIxX5n+AoRbGalHXJmwaKuRQq7G44s
         TJk3e6JlEzbBI0ypD8SYP6lJ7NAcyShVK6AbHAvLMOUX02HyX6XDdvm5uOt/QAOIWX76
         s5lEWXjvVXcfRUgPqnGGCZ+lDjWfHJKsauaxNobRS2VYw6YT6+pjiNqW778KH40z76m5
         CfIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Oa5Moq6dBHzFHKSZ6sGdJiruWwnRbMi2ob7vkXr3XeN2Qkk9G
	4uvK+aH/QbxjtSkfIAvLxqY=
X-Google-Smtp-Source: ABdhPJyazvtnRT3lYkfFw6HCSp8GMiu5TZeZS+gwrt3iPkyChLq1GncvCK5gisr43vIUYT8j+QKhRg==
X-Received: by 2002:a63:d34f:: with SMTP id u15mr7141600pgi.200.1634265649147;
        Thu, 14 Oct 2021 19:40:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3d45:: with SMTP id o5ls6075691pjf.1.canary-gmail;
 Thu, 14 Oct 2021 19:40:48 -0700 (PDT)
X-Received: by 2002:a17:902:e282:b0:13f:62b1:9a06 with SMTP id o2-20020a170902e28200b0013f62b19a06mr8613537plc.1.1634265648519;
        Thu, 14 Oct 2021 19:40:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634265648; cv=none;
        d=google.com; s=arc-20160816;
        b=bXiqyLINjP0iuQyVYXFix4Iztpvd3zrhHNOZFiiWc8XgpXi0SSxE2xR2BwGCqrhaEL
         XWsvFopI2KS/uR5LDPzvkR34FMhqJlgeI6+T+Rs5Fg8EDS30UU86MG9KPwzUHUpGWK9n
         5jA/IQZLME1nPH/CL+Z3FfXE9fQpsNn0K4A+hewxE1FaE/mVheP7EhF2nzYne0MGKQt3
         nJbC1hwf1n9F+DQ4LonucqBoXrWlzTf7OWNaIMmlCG+YNoLmkiGpJQ2njM7yT8mo/65K
         0aG6o5jyKk/QscoFSeOvsNvbOH4JU5U9oL48N/gDfY3MOFt40N7O5WDkGCCrZ01I4SV5
         CicQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:dkim-signature;
        bh=1z9J+dqYZ0Lm4fpS0d38asO4WoVCpgoJ+AZGclBygSw=;
        b=UlkIC3ZD8HHXVvs9QPe1t8ZgclHD5+489DcOXcnjAxR0SMeVME3H8wZ0BjuRj67UXD
         1SW7KDxLy+PBhz1fWJ1MIWOwRS99hGbZ6Lm4JDwjYdQHo/22rqerD2nFby5TRu3lbAP4
         Uz/lTmBqABf/Z+NfdAZy9HvoWLalxf9w1f1sQRWha2CezZyOuG67Q0J5eHokC/5nw5QG
         fj983VBOzrD4rXfx+xkx4/mb61cbYzrFKeSDyc9C8zOKhI37C0q0zI9C7wKwj6QKfWOi
         iOtV2zXoC18qpNS1xe/cBmgsSGIITeZWiP2dUlf84TA5iRaJyMtrOKF1VlGLwa5wPPQQ
         Ox4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=EvQpgtaA;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id r7si2029287pjp.0.2021.10.14.19.40.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Oct 2021 19:40:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id oa4so6216307pjb.2
        for <kasan-dev@googlegroups.com>; Thu, 14 Oct 2021 19:40:48 -0700 (PDT)
X-Received: by 2002:a17:90a:4801:: with SMTP id a1mr24227600pjh.156.1634265648055;
        Thu, 14 Oct 2021 19:40:48 -0700 (PDT)
Received: from [127.0.0.1] (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id kb15sm4048938pjb.43.2021.10.14.19.40.47
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Oct 2021 19:40:47 -0700 (PDT)
Date: Thu, 14 Oct 2021 19:40:45 -0700
From: Kees Cook <keescook@chromium.org>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Arnd Bergmann <arnd@kernel.org>, linux-hardening@vger.kernel.org,
 Kees Cook <keescook@chomium.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com
CC: Arnd Bergmann <arnd@arndb.de>, Andrew Morton <akpm@linux-foundation.org>,
 Marco Elver <elver@google.com>, Catalin Marinas <catalin.marinas@arm.com>,
 Peter Collingbourne <pcc@google.com>,
 Patricia Alfonso <trishalfonso@google.com>, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/2] kasan: test: use underlying string helpers
User-Agent: K-9 Mail for Android
In-Reply-To: <b35768f5-8e06-ebe6-1cdd-65f7fe67ff7a@arm.com>
References: <20211013150025.2875883-1-arnd@kernel.org> <b35768f5-8e06-ebe6-1cdd-65f7fe67ff7a@arm.com>
Message-ID: <721BDA47-9998-4F0B-80B4-F4E4765E4885@chromium.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=EvQpgtaA;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::1036
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



On October 14, 2021 1:12:54 AM PDT, Vincenzo Frascino <vincenzo.frascino@arm.com> wrote:
>
>
>On 10/13/21 5:00 PM, Arnd Bergmann wrote:
>> From: Arnd Bergmann <arnd@arndb.de>
>> 
>> Calling memcmp() and memchr() with an intentional buffer overflow
>> is now caught at compile time:
>> 
>> In function 'memcmp',
>>     inlined from 'kasan_memcmp' at lib/test_kasan.c:897:2:
>> include/linux/fortify-string.h:263:25: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
>>   263 |                         __read_overflow();
>>       |                         ^~~~~~~~~~~~~~~~~
>> In function 'memchr',
>>     inlined from 'kasan_memchr' at lib/test_kasan.c:872:2:
>> include/linux/fortify-string.h:277:17: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
>>   277 |                 __read_overflow();
>>       |                 ^~~~~~~~~~~~~~~~~
>> 
>> Change the kasan tests to wrap those inside of a noinline function
>> to prevent the compiler from noticing the bug and let kasan find
>> it at runtime.
>> 
>> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
>
>Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

How about just explicitly making the size invisible to the compiler?

I did this for similar issues in the same source:

https://lore.kernel.org/linux-hardening/20211006181544.1670992-1-keescook@chromium.org/T/#u


-Kees

>
>> ---
>>  lib/test_kasan.c | 19 +++++++++++++++++--
>>  1 file changed, 17 insertions(+), 2 deletions(-)
>> 
>> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
>> index 67ed689a0b1b..903215e944f1 100644
>> --- a/lib/test_kasan.c
>> +++ b/lib/test_kasan.c
>> @@ -852,6 +852,21 @@ static void kmem_cache_invalid_free(struct kunit *test)
>>  	kmem_cache_destroy(cache);
>>  }
>>  
>> +/*
>> + * noinline wrappers to prevent the compiler from noticing the overflow
>> + * at compile time rather than having kasan catch it.
>> + * */
>> +static noinline void *__kasan_memchr(const void *s, int c, size_t n)
>> +{
>> +	return memchr(s, c, n);
>> +}
>> +
>> +static noinline int __kasan_memcmp(const void *s1, const void *s2, size_t n)
>> +{
>> +	return memcmp(s1, s2, n);
>> +}
>> +
>> +
>>  static void kasan_memchr(struct kunit *test)
>>  {
>>  	char *ptr;
>> @@ -870,7 +885,7 @@ static void kasan_memchr(struct kunit *test)
>>  	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
>>  
>>  	KUNIT_EXPECT_KASAN_FAIL(test,
>> -		kasan_ptr_result = memchr(ptr, '1', size + 1));
>> +		kasan_ptr_result = __kasan_memchr(ptr, '1', size + 1));
>>  
>>  	kfree(ptr);
>>  }
>> @@ -895,7 +910,7 @@ static void kasan_memcmp(struct kunit *test)
>>  	memset(arr, 0, sizeof(arr));
>>  
>>  	KUNIT_EXPECT_KASAN_FAIL(test,
>> -		kasan_int_result = memcmp(ptr, arr, size+1));
>> +		kasan_int_result = __kasan_memcmp(ptr, arr, size+1));
>>  	kfree(ptr);
>>  }
>>  
>> 
>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/721BDA47-9998-4F0B-80B4-F4E4765E4885%40chromium.org.
