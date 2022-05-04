Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBRWMZKJQMGQE6YS4OPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 14F5751A50D
	for <lists+kasan-dev@lfdr.de>; Wed,  4 May 2022 18:13:59 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id h7-20020a056402094700b00425a52983dfsf1054554edz.8
        for <lists+kasan-dev@lfdr.de>; Wed, 04 May 2022 09:13:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651680838; cv=pass;
        d=google.com; s=arc-20160816;
        b=I5fkyDwc4FtrwGL0Uew1o0WM9vXCFjt4J6SfpGuTn9t8VcIenrEQDDTIJia4mXB4pb
         xSInZtJZKhR0/svhFjkhMRU3ROdAMf+71v2DkT86Jsk2bgvIdpCKscHfoXWOvrqNZo1f
         JrlhXzEQN/Gvia0ViXE58Kd2LMgzBO0WC6P8LPEbf8ouQKEZEYWuAIRB0Yfxl8Ie6QgM
         j+aX3kKqFzzTkmBb2nqrkHQsA1StWfxfkFtXa8ZACR/ov2wJcATshWnNit08wBVKmA8g
         1+d6hOHqR3dnaUrDjH3zSTZwjCIOBrTay/rvdX8UIgr1jtdOCOx1pjX7mFW+V/emy4QR
         CsAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=F7jOV+8GVzXczmMYlfXyjMiL2OvJhvlvp4kvAdg4GQY=;
        b=EwlqbMqxlfifEYLpJwGCFCnpY9ioEzAqa4EGXw0R25NnRW8w8IgazqQQ0XVrYY0Wrn
         xmUKVqQD+21Q1pN8yCdmI/PuQMeoi9Xs+C9nqu5h3tJHYhcASrXnq4ILSK827LUVLopw
         hLHZii0Ojp5/TLVf0Y31wAygX05ix7VwLZGQkn+dkML6LNm3mcQF6OiFomV9FR0fOJEx
         9yHQOHSTjM/qf3K1kzSYjV7o+pezHIApzz9aRnQU15RdUKNr4iW3L7oGP/aM+vR4B8pp
         3d1nix+pcJ5gQuezVYTEeRjiKuOsQwauOVe8G6dSDWuCYs4r0cUTa60H58xobFjEvCZO
         8yGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iooNSkkR;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F7jOV+8GVzXczmMYlfXyjMiL2OvJhvlvp4kvAdg4GQY=;
        b=awkfFxKDm1xVoxV7zweJZgKVN9qyuvetksOZTTIWoUyv59G00vqGeHmJUvLwBzHKah
         ShHSUvz/tV1rq7JnILl092UFDwkXFdC/h9TpohVTO1kqnT97KAssWx8NoZKMN+//Qf+G
         dyLF5prV0yyWZfrBkfhYC3jxzRaULtqP99XfRONFb7tBtK5UtJ6V1lglynmOoyhYYJRw
         LUMJGfrjMw1VnUuDpEXUs7IwxO8lU73MTcFBm967lQ/1SjdeURunfAKUWv5PPaM74bLW
         TzTjzdqcV9EuYz8Y31ONgrJY4F5x5NZf24onK8F/xruao08XyXMA7B99cdwUXW9PTslx
         GT6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F7jOV+8GVzXczmMYlfXyjMiL2OvJhvlvp4kvAdg4GQY=;
        b=QbHRaI/lyEp/hmhgR6xkC/tBcwYuELc1iCe9uanXYjdmUzRmceKql6z3Dvgk1sLtKe
         COsGOZdSYYm8/kyarkQx1taE/8Shx+3ffDbz41nP0NuIMSoi++8GliGOClY+Ma+xfOBw
         5IsqhonpTf09hR6mkmkwum7v2TJuKmYxGig5LJkeKGS+FdApZUo0mFmDdPcFzdKPENZE
         /lQOHWhvD5kTU8GtVtSNHnssWTH8cudBS2eq1l6ltZc+xotlRa6QUT2BNnFrjEUKm0hZ
         b4GVFH6a/PaGH5DgQvpJvGxkG5NdKkrLPuKdIPv9SRS93HQIQtFvug/TjOAvGUPnsacn
         gRzw==
X-Gm-Message-State: AOAM530U0PHtt49jmCNoW4OIdaNKwOe6ZU5BftR2yGlI2Iylu6P9KqHp
	8OiwI+LZPEcraRbJL17en9M=
X-Google-Smtp-Source: ABdhPJw0b44rVgkZuaZe+oWZI11ZiQlSHgTBH9HnyA/AIZKZlLV0nCucALPsvUeG3KKFEQFiv+BkQw==
X-Received: by 2002:a05:6402:2815:b0:420:c32e:ebe2 with SMTP id h21-20020a056402281500b00420c32eebe2mr23459038ede.1.1651680838573;
        Wed, 04 May 2022 09:13:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7ea2:b0:6f4:dcbc:baa9 with SMTP id
 qb34-20020a1709077ea200b006f4dcbcbaa9ls276778ejc.2.gmail; Wed, 04 May 2022
 09:13:57 -0700 (PDT)
X-Received: by 2002:a17:907:2cc7:b0:6df:b76d:940d with SMTP id hg7-20020a1709072cc700b006dfb76d940dmr20470969ejc.742.1651680837601;
        Wed, 04 May 2022 09:13:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651680837; cv=none;
        d=google.com; s=arc-20160816;
        b=VIu08TnzTTg3tcuJ1X2+QnRA9Hjxx4NCe/bkEmvmMs4v3GpOdPIxS2ioOx1LKunO00
         zDfAaH2r/0ttUbGROyLdPiaXjpMujZXgPNV+ndWlWU0Ftw77OZUDPm+NYGfXQJ3yl+Oo
         iBHGVFmjaNNKsOZ6R1kL5E8gOyRl7k01RQs8l1MKnreVk9I/o3LAeo+XXbHjhteNInFP
         CSYdRvY6oe9RKpPd6A3XCYY3QI9vPCrA0Fu2Xxz7mzWjfiAevR0m9BUqqH7zMAqvHZGo
         iARTGzWV5OvGk5ArYEFawtMTktu5hj3zRtWTZbOsqHeVxoCYzbBEqF1tffiod7mwxV9T
         7GwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NyjmBJU8zwTbLFeMwf6TGdRUSj+gIVdGN0MnXtRxNME=;
        b=f9SfOuYlwkouakpYaKKGOvZgTm2h8+oGU1+Ck9BLvW3ZHlr+yevkHhm9D65YQSmqXa
         mRkUG9N+inmEtbirROOSDYFD8i7GCDFsXKKGH0TX9jKnnXucKHVt8eHiV2zwU0VY9iAr
         GuoDZM3LHrXNBB9qGGAV0HdlScPVpr6UpEIqda2nApseCL4od03CON7SwgzXSoKRmRVL
         cU9qPZaIZpIwXh8al+J6uZ6oJIOc+PgKlvTGH0kofBoYX+dvMNWetepnXeGefyT+Wps/
         w8DlsialJMxXFtG8Ld1LkUUcqeYlNOEGt6u03YCU/97FzSzTsxQinjYq4d2IFU+hs2K4
         rx/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iooNSkkR;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::631 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x631.google.com (mail-ej1-x631.google.com. [2a00:1450:4864:20::631])
        by gmr-mx.google.com with ESMTPS id v8-20020aa7d648000000b00425adbac75dsi1039649edr.2.2022.05.04.09.13.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 May 2022 09:13:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::631 as permitted sender) client-ip=2a00:1450:4864:20::631;
Received: by mail-ej1-x631.google.com with SMTP id l7so3861009ejn.2
        for <kasan-dev@googlegroups.com>; Wed, 04 May 2022 09:13:57 -0700 (PDT)
X-Received: by 2002:a17:907:9726:b0:6f4:c0e:40ce with SMTP id
 jg38-20020a170907972600b006f40c0e40cemr20324048ejc.170.1651680837175; Wed, 04
 May 2022 09:13:57 -0700 (PDT)
MIME-Version: 1.0
References: <20220504070941.2798233-1-elver@google.com>
In-Reply-To: <20220504070941.2798233-1-elver@google.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 May 2022 11:13:46 -0500
Message-ID: <CAGS_qxq504dLbF_MWaJwNqLobjPAdZ2HOBFAiivpDE_WDYN+zA@mail.gmail.com>
Subject: Re: [PATCH -kselftest/kunit] kcsan: test: use new suite_{init,exit} support
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Shuah Khan <skhan@linuxfoundation.org>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=iooNSkkR;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::631
 as permitted sender) smtp.mailfrom=dlatypov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

On Wed, May 4, 2022 at 2:09 AM Marco Elver <elver@google.com> wrote:
>
> Use the newly added suite_{init,exit} support for suite-wide init and
> cleanup. This avoids the unsupported method by which the test used to do
> suite-wide init and cleanup (avoiding issues such as missing TAP
> headers, and possible future conflicts).
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Daniel Latypov <dlatypov@google.com>

Adding '-smp 16' and CONFIG_KCSAN_REPORT_ONCE_IN_MS=100 as you
suggested below, I was able to get it running under kunit.py with the
following results:
Testing complete. Passed: 168, Failed: 0, Crashed: 0, Skipped: 1, Errors: 0
Elapsed time: 92.642s total, 0.003s configuring, 4.592s building,
88.009s running

Nice!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxq504dLbF_MWaJwNqLobjPAdZ2HOBFAiivpDE_WDYN%2BzA%40mail.gmail.com.
