Return-Path: <kasan-dev+bncBC5L5P75YUERBJMS3LXAKGQETTJZSDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id F06E9105275
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 13:55:01 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id u17sf895589lfl.9
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 04:55:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574340901; cv=pass;
        d=google.com; s=arc-20160816;
        b=eHgBJZhWD2lEEKhVo/3IZ+ESaMu7Phb8vv6lh9Sd32WPFoPkN7MfL+AQynaR7GRnhv
         kRgjJivHCpXs8r2qaXnTkPp6u4loIYx2lQF03DLSBZGgkHVfGRBPLv4D19su2C8ovsBT
         cAlFL+uKv0OzkS+/kc7RgoLI1IEMTfX9sra+i2vGcuN4V6VhLBxWhGjhZEkF9H2QbbdR
         05NbwLRvbqTH/ieAonQlMPmaXnp2dUglLTg4zRvg0u2A89LMdL4pzmLYAjTzrCs90N4H
         z93I0U/3uAaa9UG74yF+kC4WEwLYGgfeILpigKaLHzj4cnQwlPfVMzcIpsrMPaWJBZJr
         a8lA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=U16UBIOdqF/UHCmsLHYojUEYpjmFHkKMTSWyauxbx1I=;
        b=Caq4sTg0lqwfi7b9uFAmGxZCseKNDfapYWk3EsgEM9ruuYwIvo2bqRSQnFnXtunw18
         JklJNT40m/FhGnVBKFpZYvoV5mdiLa96snfZaQ3cCVG8cj/AQuuZBnlJz/JdTtSg2PYd
         0/DepJGOUoIRZezx1roc8vTFs4+28QmMLd/GQdngOeqH6QIvwyVu0LKc9HQ8S82VjDRC
         8Esx1PFeMLuDhKtaZocXOgGuDybTtTZYRT6qw7iXXUkN0XmMLwmKsxNodxKx7bf1FxT2
         HsD7pYY1HbjDZM+QcuhLx/W4oCOjwNfHiYrjjTwJfb0mg9kTZZ2AI/ewiti7R4Rv9CZa
         qohQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=U16UBIOdqF/UHCmsLHYojUEYpjmFHkKMTSWyauxbx1I=;
        b=pXdrA4IwSdzclsCViZ+LiaSQHIptIQ5sUoNwVela9QEsw0y+FXN7L7pfdwQa+HoQ2V
         RwFq6Mbj4ZbEG3Ff3XX7PhO9RaaY1j/3pqRp6Bx5pYVJtJM9+zoI7r9EtuU85Hfu6q49
         iZUm1RnNGz55Tk/luKggB+75BAQ8a4lYiPXHKHR4y57mKexwFpSCKRGvAbfa1Q9A7I25
         bgWydgAK2g83hxqoLJDYC4rB8oIUYc/cTeiN/R6PFriiKQlkEXbYHPDVEwce3sqVZ0Tb
         PL24lZtrUCejh3M1Xf1NaV77vSaK7f3IhxskP1ovZpqAinj1/WtQ5drqNS2QuwuwnB5Q
         dLmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=U16UBIOdqF/UHCmsLHYojUEYpjmFHkKMTSWyauxbx1I=;
        b=hAtenG9UiFPN+AnbmYompfvniU/fAkbs+ksNCBENaN2XQfc+OhdYNSuCQuIZILD3GM
         SMpEGn0uGB33gHRyl0W+N+LulrspbkPgVEECZ8zuvqGrJvDt2iZasH9jSuYfBpuQIGKb
         tNQ43R/WqTVLZDizoTm953xK71fmy0UcCLO6C40C3qf0i+mLIT+C+rqxsJrx7aBKm6l/
         BWqXVJeNI+zVEjRU+/jHXl0Twii6T8E7MpNJ2YlxGdMWiohV9Yv3vaFST0t1yEu8kmP4
         4kBHHe6ImkaTv+V5YwsdRXW2Na+cEIP/knpnA08pv+53YRYeTHUYMwZNFTrKTGx3i5MZ
         f+NQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVnJ739SE6lKR8UpNvSTQXhNVAWlzzxudaHz+EQhVahA4j8emov
	7ncvtwYHkPsCUo4yFVrkF9U=
X-Google-Smtp-Source: APXvYqwtTY9Q0rgP4nwqjnNbsbD5x8jA/sEe5C25kiPb/tOANQOv/C0u9rq5SWvzlLjUQBySeXdPZQ==
X-Received: by 2002:ac2:5216:: with SMTP id a22mr6943571lfl.18.1574340901537;
        Thu, 21 Nov 2019 04:55:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4184:: with SMTP id z4ls725949lfh.9.gmail; Thu, 21 Nov
 2019 04:55:01 -0800 (PST)
X-Received: by 2002:ac2:4ac1:: with SMTP id m1mr7561596lfp.182.1574340900966;
        Thu, 21 Nov 2019 04:55:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574340900; cv=none;
        d=google.com; s=arc-20160816;
        b=NK03YQvBvTRtqCr27lfD6B8haSaqKJuKPcRpqfPaK5Geemht3j5wxZ+SId67MUOJWB
         rKtGG+tK+wR8jutdU0VXlyS7p7fs8mBU6PSC7RmBdBHf28Rl/+xR1mVNzuMASwi39Xyn
         gVkW+OqoXEOrCQqzUM9JW8bjYt2GJhDwz2t3P2T58ijutQKSlQGoVJHMWeBZ3cA1v1kP
         S+ssWVP3T9PIQz3ESJ2+uU8n8nJgukz0d9QXtxpOsNpxbBQeD60qPkJ1whytG1Ksny2n
         7l3OOvLPh1CtXuzwJKDGfNl5hJIl3X3mzUbgzeXhxlJmML3yFUk7HxCrkKvVYu8dIdk2
         Qpjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=VPFKLImHu5NoSeLCImxI/llSaCN5K5GOt05o/lt/Wio=;
        b=GdtCjcHnyGsT5E/hHe7FlCcoc7XxfhoqWLU6b9dqyt33dBsCN9XgmJxW/pjxZFLNFQ
         OLmWbFjN8BCZ/0Y2tu1JNv5nob/L1MAPgwT5yHHMDqzHwcW/lxKwIHQ2YwEUcYivu4c9
         YtP0dgOcRT6osMpOUomn5Y2kB5pPrlwFTWgaf+k/hKqUde/oJGidxKJbfvGs5hSMIlhl
         L+AQceXs5xh/H978Jpnx/6gzsoKi3ey9Mx5WMSeLjl/PoUgyAWYZKoCl9yhbDht16AzO
         gmbAqAmUDnjPDJs07BxOEwqWYQgiD02G95p34we4H+asxC5IEURaJFcNOTQfWKc0zE8Q
         U6xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id k20si98491ljg.0.2019.11.21.04.55.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 21 Nov 2019 04:55:00 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5])
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iXlz7-00025W-30; Thu, 21 Nov 2019 15:54:57 +0300
Subject: Re: [PATCH 2/3] ubsan: Split "bounds" checker from other options
To: Kees Cook <keescook@chromium.org>
Cc: Elena Petrova <lenaptr@google.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Linus Torvalds <torvalds@linux-foundation.org>,
 Dan Carpenter <dan.carpenter@oracle.com>,
 "Gustavo A. R. Silva" <gustavo@embeddedor.com>, Arnd Bergmann
 <arnd@arndb.de>, Ard Biesheuvel <ard.biesheuvel@linaro.org>,
 Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, kernel-hardening@lists.openwall.com
References: <20191120010636.27368-1-keescook@chromium.org>
 <20191120010636.27368-3-keescook@chromium.org>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <06a84afd-bc97-d2b5-3129-d23473f7acb5@virtuozzo.com>
Date: Thu, 21 Nov 2019 15:54:44 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <20191120010636.27368-3-keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 11/20/19 4:06 AM, Kees Cook wrote:
> In order to do kernel builds with the bounds checker individually
> available, introduce CONFIG_UBSAN_BOUNDS, with the remaining options
> under CONFIG_UBSAN_MISC.
> 
> For example, using this, we can start to expand the coverage syzkaller is
> providing. Right now, all of UBSan is disabled for syzbot builds because
> taken as a whole, it is too noisy. This will let us focus on one feature
> at a time.
> 
> For the bounds checker specifically, this provides a mechanism to
> eliminate an entire class of array overflows with close to zero
> performance overhead (I cannot measure a difference). In my (mostly)
> defconfig, enabling bounds checking adds ~4200 checks to the kernel.
> Performance changes are in the noise, likely due to the branch predictors
> optimizing for the non-fail path.
> 
> Some notes on the bounds checker:
> 
> - it does not instrument {mem,str}*()-family functions, it only
>   instruments direct indexed accesses (e.g. "foo[i]"). Dealing with
>   the {mem,str}*()-family functions is a work-in-progress around
>   CONFIG_FORTIFY_SOURCE[1].
> 
> - it ignores flexible array members, including the very old single
>   byte (e.g. "int foo[1];") declarations. (Note that GCC's
>   implementation appears to ignore _all_ trailing arrays, but Clang only
>   ignores empty, 0, and 1 byte arrays[2].)
> 
> [1] https://github.com/KSPP/linux/issues/6
> [2] https://gcc.gnu.org/bugzilla/show_bug.cgi?id=92589
> 
> Suggested-by: Elena Petrova <lenaptr@google.com>
> Signed-off-by: Kees Cook <keescook@chromium.org>

Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/06a84afd-bc97-d2b5-3129-d23473f7acb5%40virtuozzo.com.
