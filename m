Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEPFXOTQMGQEMSBRBLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6107D78D3AC
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 09:41:07 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-1bf2e81ce63sf545406fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Aug 2023 00:41:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693381266; cv=pass;
        d=google.com; s=arc-20160816;
        b=zf18mjHNAUoaPOpkxjhj3L9qKqwVQOXyL4d1fM7ZShD0hqmF/iE0BeafT7EwSJyokW
         1IiY62DUZf56KyBABGDwHrk17d724VJaDjkIcCtzgwUsPtw8pIRs7MGeyFmro9H/6UVx
         MufUbzUiz3pVe9g4w5aZpObynIm7UFzQqMscTL/sH/9S3JO4RFFSXcg2anaEXvB3gvGZ
         KsMu4jk4b5aNI8oLgLKfK4i5w+k2lAhMJvn0sF8c1lZPzwQlbaAHaPfHvE3gzMxvD+1J
         asBlcJK6NLa7DsGX1tjHp+VA/KFSk4H47Q2FCi7svnjM8AWxOp+pvAnNsJesUwOoWpRH
         m6Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vnn4zCtRJx7NCZ6DpPrUChqmlkIhZT9G5ynwv3vIsII=;
        fh=2tgrBxnVwcLXHayTK7pIfhTdPsNvlLazimpmxCZaT7I=;
        b=N+P1bJkXXxW8EABbb8hWc5+ugWMA/Eioz4YBSxmIYZ8zr3f7dA2OSoibq5ZdR9KTxf
         w1B71xYeBrsECtw5xTSpE8kYBbYFUPs2cxTvhTLjZI8V8NI2MZXvXVMkfkeWinWXN2rw
         aDg6JrafFYT2EXHth0y+tz8rMh0XT2n4vGKsyx03Q/AUVUDrQCOTyQOMh0hh0YbQKxHE
         /8wa8hQVqdTwHtENEBjk9vAIG0RUoCYx0QpQSx2DN1lIvCfTDlRoiXvIanLptjIxPTBo
         eHZUUUmXF6Luu/UxCrYunqrbwveu3tNf1ed8XVH0btdTfhLHW8OYwzqlcAmFq5oZFNkr
         miEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=PkgGPFxG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693381266; x=1693986066; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vnn4zCtRJx7NCZ6DpPrUChqmlkIhZT9G5ynwv3vIsII=;
        b=q1R/UQsWQSg7DLDXDB0rECLAa1eeBN9lJdgyPoTfnQaYZ/APYtcDGwdjiwdiSsG4v7
         x0OTEezh/qjAD2cMjP+xOSYpQfuFu455QfJiB7sdFowctA7CvztgGABIMs6yN2faV78V
         SjErDTXX9invTG9HtingYCzd60nSEi8uh4VDAvdJM6yr3m1FXqYVVH6IRrUVtJBh9+x8
         h/9N26qXeBFvgOUaUkzBphvoikwafsLP/VIaQcdHpOo3Q/c17lt6tm6aPgIFLV1HOHSC
         m6gyygEZU5kq7AI/QjyeNKbLB5nHLQuN3P3EyHh/yJk92QyIXf9COdhtIiDK1aVFZpo9
         lAfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693381266; x=1693986066;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vnn4zCtRJx7NCZ6DpPrUChqmlkIhZT9G5ynwv3vIsII=;
        b=fRzcuaDuJp53Y/CkMILPzZZwb+Bx0Z59LnHM+cMtBncz8uad5OjaWbQBwLm8JYP22G
         2yHkVLVlOStAAT60mW2XWL0IgE5eGXD6Iio4iYcR/cnslVlL+DeIVe9kvySX74y4F0Md
         oXAihaxSFWFtu7M0U6+tovj8YKpdW+JG7vohsuyLUaFis0+10eIACGds0yx554mxe5pR
         a+6k1pFaN5VZiQQiqFaEv4441qf6xBE2qxQYKmecZLzP18sBOLn4Odo1nf1lMlbxqCMs
         sF8vWX+F0xlKV0SOpnMplVtVeMbSeJGG8mwbhpG6p9gIm60RuqA1AU61lUqDeros8dUL
         qxzA==
X-Gm-Message-State: AOJu0YwR5zy/d1CGODZbcLRvNdh1rtmUOuiURtpPB6Qw0VX6JJK9UQgU
	4q4l25JpoNJ+Oo57nNNaAD0=
X-Google-Smtp-Source: AGHT+IH3umjiUP+ZJNvLNDGrKhNEYfODGj6qrGsAXy0b5qsAS5EiZBOMS4vofoax6lHalkucXDMKeQ==
X-Received: by 2002:a05:6870:738e:b0:1a9:f6ba:138a with SMTP id z14-20020a056870738e00b001a9f6ba138amr908213oam.0.1693381265755;
        Wed, 30 Aug 2023 00:41:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:8b0b:b0:1d0:d238:553 with SMTP id
 tn11-20020a0568718b0b00b001d0d2380553ls873486oab.0.-pod-prod-00-us; Wed, 30
 Aug 2023 00:41:05 -0700 (PDT)
X-Received: by 2002:a05:6808:2107:b0:3a8:8470:fe9f with SMTP id r7-20020a056808210700b003a88470fe9fmr3103508oiw.3.1693381265100;
        Wed, 30 Aug 2023 00:41:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693381265; cv=none;
        d=google.com; s=arc-20160816;
        b=qe1ErFz+dd7x0JNDu+6d+6wdJbDzG14Fn1i+ub7uR4s2RpvNmNtNu3HkKljx3QriOH
         FLfDs+V67W7uUbA2MafAdC2eHus3ZuOBlEOBEhse1fNs9D4tEgSP+wMG/AqPHxy3DFX4
         Gy+zW9OUps/SlZgb6E+2dfW1kPo1ZIAfm2K2V8ltwq4qG0zs0of8Dm0EtEB8I27q/tEE
         AG2dXCTmeYsAqWsYus05UrekXmUp7ERKall/kUL5SAWoaSOf4LJxeuq6ymdPQGim+15J
         xTUPZQEYphCto/sNoxF6T1Ty1LrJ0SONXzsepUP8s87BU8oAwLXUuxIv8DMmuMBXUSzt
         uAvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=bL07VE0OwJGqoGj8jsKtJTE4qZZ24p0Xdc0kh4JlWO4=;
        fh=2tgrBxnVwcLXHayTK7pIfhTdPsNvlLazimpmxCZaT7I=;
        b=03jUIOszF44sK5Ev4wMyhqflIt1SAhZNXLIheGh/qbBbYB4JV31UenffZJ7Osjx2Ra
         8sfDY5BbEe8C+jAtC4Zl4UWxp7qKet9fL7Z2gi1EJxwt0LqHYimxwsFlialu0t3v4dNF
         C3zMzi/2W1Oirxf9hqFKVu+7iFrZ4MyNXlrrbpsr5q52osWcMRFY0OVjJmL/TS0287lF
         2kA7NluGLpYlRDxIfhzbJWRjn9By/pmwf2/7voLzRf4RMLqCrp/Kj4sScw0OuVjlhcJN
         IVnNJuZfByIPxJoh80WWXeZ7r+L186uPS5EKG0v7SxXH1puejdAdccFQsOpR00GdGTQR
         FzPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=PkgGPFxG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id gu15-20020a0568082f0f00b003a8a0b717ddsi1752935oib.3.2023.08.30.00.41.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Aug 2023 00:41:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id ca18e2360f4ac-792409bc1cdso15249339f.0
        for <kasan-dev@googlegroups.com>; Wed, 30 Aug 2023 00:41:05 -0700 (PDT)
X-Received: by 2002:a6b:e811:0:b0:792:93b9:2065 with SMTP id
 f17-20020a6be811000000b0079293b92065mr1294332ioh.7.1693381264582; Wed, 30 Aug
 2023 00:41:04 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <43b26d397d4f0d76246f95a74a8a38cfd7297bbc.1693328501.git.andreyknvl@google.com>
In-Reply-To: <43b26d397d4f0d76246f95a74a8a38cfd7297bbc.1693328501.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Aug 2023 09:40:28 +0200
Message-ID: <CAG_fn=U1GN5TH7Mm80uvrOEhmNUD-65Tyh0qgm-v=w6Bfape8A@mail.gmail.com>
Subject: Re: [PATCH 01/15] stackdepot: check disabled flag when fetching
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=PkgGPFxG;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Aug 29, 2023 at 7:11=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Do not try fetching a stack trace from the stack depot if the
> stack_depot_disabled flag is enabled.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DU1GN5TH7Mm80uvrOEhmNUD-65Tyh0qgm-v%3Dw6Bfape8A%40mail.gm=
ail.com.
