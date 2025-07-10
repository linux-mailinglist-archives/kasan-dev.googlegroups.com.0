Return-Path: <kasan-dev+bncBDW2JDUY5AORB4XKX3BQMGQEQR6WKHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id E79BCB0023B
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 14:43:31 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-32b2de6033bsf9915361fa.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 05:43:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752151411; cv=pass;
        d=google.com; s=arc-20240605;
        b=DbZ2BS4lD6uzkzbbULfvmAkAYF4r+3z7GeGYis6IIHAx6f4BJxfaAntKAPTAZt3FmM
         QJY6KwzxWoBfK0PywoUQf9PSr6AlnIfp82X9GpyQV59cfdfPDeeRe0G9kVIe3j2BkW0e
         ntaIWLQUhq2S9Ajs5wkfESzbXmkY7yWQkrR9f+BgdEOGRWupNEahEGphgcxI0WC5o0VW
         mXS0a+/uXYHkvfng3Ih6RoZiIlDX49RU5kcbKBlmK+twmn56K1NwQrR3QFhjw7GjMNQs
         kK7yDFWvJKGw8nGfKUU1+Qyh1GREypyygCNulhHf2fI8OL575gAIPQJcW4Qnbu439gy2
         GCjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=St5ckUMUGP/NwkabmHh6YgaTYGOoHC4doBFQCpVWx1o=;
        fh=xsT9o9NfJLSleywTOm4L7UGyI3VHZ7BBGJbaW361MeI=;
        b=H5RnNrRwwSgHcdMv6fYkveLzy8Ok60MR2Ig/SzOCpkakunPswdskFzOah7vXvhzVb9
         IiqdtYMbNpk8FJBNr2LdPUyVJMayr4+CkdCEnyZC9n0NHd32dDyQXUOAMS2r+wM5Lgda
         yGo6c+NSeX0ZnMAiJD4TmmCrKMtQBz2h8KChwXEKSGZSTxPbGJHZsq+Te8zzatxcXKXJ
         RVxxldbtA/DtTwTznZ7bhg+FyWv/+Eh2nQxPHfhR6fAGbeAd5zD3OAG9v6+c4ndK+rWu
         vGXnM8XChcwsnXHVRA4veIBRtgmSYmt8KD5qsaAMx9gJpdfvd91L8sm6vf7xaC9P9LAB
         eoIg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EDDFhVWE;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752151411; x=1752756211; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=St5ckUMUGP/NwkabmHh6YgaTYGOoHC4doBFQCpVWx1o=;
        b=Hfscjw1n7uc1ztVb3tBRLn1ttmA0RpaZjdW83h8w+it7IRLoNKXFaE4oUBpNXL7kQu
         nU9d8p5gLNujlhi0Is8V9Hj++SJei1l/T9dyTfWyUpS15VDdF15Qnl6ME8AZ9B15lXml
         ExWFzEx6H1bRmiISDjIwA2kQLcIQ2Mh9kgylqfDs6wZhmKFd8JudR4RzrXuvVLoBM4bR
         yZ32ZULLHi/Nl2cWr1Y01br/jV+ULXMFwXDvIm0law5BiAuzlm/DsJoTHpYOJDQOVNGm
         AVU+rFCx76l5LgkwoDtF7BDhqZWN9QuGAOpVZnIhtgyIovGmjheSYnn73brSg8mPMcfo
         UjMg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752151411; x=1752756211; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=St5ckUMUGP/NwkabmHh6YgaTYGOoHC4doBFQCpVWx1o=;
        b=k010D4oyztVgPIKsBRJNTw2ukB03TOMYYUa24MyUopyK69/x4CjzY/yzV0MW8IQA79
         x4GrYmAFR6KCpnsRzHQZmZ365aBVaY28BHGZpIKUzunwSrY5onmzyqOABFh/ovHZ9kwv
         gNu5QkD5OaKeyJkAADLtDGkKa3KznVWqzONGTetQCyEgb06e+VWPPv8a7ylaZKiJ7w7y
         2a/cnQdCzCcw8lnpVkyBze3nH9A5zMAdN/Umc7WrAE1W1Qj8ZpIza/JVMfuiRFyvq3NL
         iNVhhCD/uiJJwVvjMSaT2G83S8I3Pq1vK7KBNXb6x+FuJnZTtYbRIMf86uMJF+8DCl6y
         EQbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752151411; x=1752756211;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=St5ckUMUGP/NwkabmHh6YgaTYGOoHC4doBFQCpVWx1o=;
        b=g8fX5aDuAqEM8a+Yx5zdBeha3N7tJXYQ3cXNdhrkPQGoMoamOcNR44bL4CHG7roNLq
         H2Tr8k65t0sOsxZMgahe8yU5ItPf7CRWeoFx75PBx4I95VpeelBIWDiDHSBOclIIVucb
         QMY5vNOgDK8eX6LoSRDPnIA/WWax3p2haZU0SPAfEwOcEWx3IKwjIqMqmy7OC1pM5dhR
         cMEabN4d4gzpvsvjojT+sRVY6kPHCgWF7kMK1DBjb3eIq1CeqjN4BIE2a3bREm6PxMWs
         YuXlUgzhTCNkLFxr9E8ZdJonc/Vnq6FtulXOneG15ccw4FUd5ZRExa5CJ9ENttcZJpTZ
         tEXw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV1OQfDG41UmFwita3T/FY7Es0LvbaQ2V/cfcVTd/+FOTG7bCCiooLVF0/0qXRoVHhBtEYBdA==@lfdr.de
X-Gm-Message-State: AOJu0Yz4VcolVmCBGtdunau8cbk2mZ0ml/XWd0WKU4fRD/PMPX3Z1FMm
	AcsRO6IjnUhzq42vVdrSmSJ2WYllzf3y76N/EhQbCJKaOvXtyG72aCg1
X-Google-Smtp-Source: AGHT+IGuCBpt2iIT0e5JRrhbVGON3Gn5fQcrZIka14vyJ+x1oxB/3fRQB5tCZ9bTyIymjZFYjvNosQ==
X-Received: by 2002:a2e:95cd:0:b0:32a:6c39:8939 with SMTP id 38308e7fff4ca-32f50fe1c67mr9993401fa.19.1752151410830;
        Thu, 10 Jul 2025 05:43:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdXy2BcsS3RBzkwQicTzn/BUJPW92hKm71DYIfkb+y3pw==
Received: by 2002:a05:651c:11c4:b0:330:4b06:2cc3 with SMTP id
 38308e7fff4ca-3304b062d76ls844671fa.1.-pod-prod-00-eu-canary; Thu, 10 Jul
 2025 05:43:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWIN8elHpkuE43xcQSJsRcriL66jLnt4rg0H172E5XYEgZ+kfkIAkrHfsNyQQeWcduahvqQtU7j5Ag=@googlegroups.com
X-Received: by 2002:a2e:b544:0:b0:32b:c74e:268 with SMTP id 38308e7fff4ca-32f5123b291mr8009431fa.17.1752151407761;
        Thu, 10 Jul 2025 05:43:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752151407; cv=none;
        d=google.com; s=arc-20240605;
        b=USlJmdYJDlxw+f0rZ5fcsennVYJSgEuKpEcV9SiB44dErGc2C2fjblJMd3Pl4ZSCvI
         AQ31hGIqO5J9RqiDOm1/nHIA7Eq0AHhYIpMjl+4ZG5HU8fNRieYGoboFNpRzqbKPleuT
         xYI8AMM4Ryz1A6k45GR5ln/iWNzEiAH+7veYRY+Ch2cnRdq6/fiv+pUqRyYbwbARdLiK
         HotN1507z3sWPA6engOW49LK6Gv23LlYV3UmZsx6Y5JzOBT8Z4OSzi4GcDUSOvkFQsF8
         Dv0Z7ZMwxGzxjUQOhRbVjxGjXij2SVDaZzOPEc/fZknEB0Qa1JWZzgP7x8ZrFDlz3oYY
         rUmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=RLZ3wT/zIcTlhpVZ66G+GThU9XAAh1rTUV/NBZEfAJw=;
        fh=caun1HCgQknCqaiAXv12NE2Lqk84jt61IxXZTKroczM=;
        b=FAk23P9B95X7QO2J8N+VIMVTeChyIny/18ebAW0kFH5BV4FIH+RV4LB9iao0Fi/SuA
         bE/WQqtydzlTwvGIjD9CZ+0rG7qrPY9N0fv6OB4pnD/10u/oKTnWc2qHdST9Rlh6cnc6
         icZvuFL5gyCVeXdIeCffEt+umaosK86Y9rCe94UHoZymSEptSwbkY40G9eQ3kTR11P6s
         FbDKjT8ThHIP75Yki6Ylfg5wxgxBgb8nMbONFZjK1Q4s43uzSq5n2nLs9OH1tWXrI/Y1
         giAMbx3sLlUHX0XXcjkKznZoDJ575DCEdeIYzpAB7JhBb7nA/b8ge9BpxKayHfbO1HUt
         ogGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EDDFhVWE;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32fab84ef66si397251fa.8.2025.07.10.05.43.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Jul 2025 05:43:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id ffacd0b85a97d-3a4fd1ba177so678187f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 10 Jul 2025 05:43:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXtVyDxTkU+Or0nQyWbnJczy9lzFI0BEwkS9xVE0w6kfFWLOzsrdasnRhoxmP2aXyF8j3joHGDQyMI=@googlegroups.com
X-Gm-Gg: ASbGncuH4hyV8yE+JZxHXuKBSunD6CgDmqgOhcCTg7X1LzHlY0RoSlggLl2WZCjbBRT
	v3Azo3Jb1J4xn44BbUNOz/At67KAORepBpidd44acqzsr7TESeOZ8Z2sL+gyFld3UOgy0HDiLIS
	nyUsjD5d+ihqXxMuPjcURhzjOWKThTVSv1OQWzO83d/uWZVw==
X-Received: by 2002:a05:6000:22c3:b0:3b5:e07f:9442 with SMTP id
 ffacd0b85a97d-3b5e7f34672mr2613771f8f.19.1752151406804; Thu, 10 Jul 2025
 05:43:26 -0700 (PDT)
MIME-Version: 1.0
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
In-Reply-To: <20250703181018.580833-1-yeoreum.yun@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 10 Jul 2025 14:43:15 +0200
X-Gm-Features: Ac12FXxkeNT4SbQnhPymL-kgefhQmsJ3o4VsRU7W2osYTS5GaGgeUo2hYTeE0yw
Message-ID: <CA+fCnZcMpi6sUW2ksd_r1D78D8qnKag41HNYCHz=HM1-DL71jg@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent possible deadlock
To: Yeoreum Yun <yeoreum.yun@arm.com>, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	bigeasy@linutronix.de, clrkwllms@kernel.org, rostedt@goodmis.org, 
	byungchul@sk.com, max.byungchul.park@gmail.com, ysk@kzalloc.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=EDDFhVWE;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Jul 3, 2025 at 8:10=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com> wr=
ote:
>
> find_vm_area() couldn't be called in atomic_context.
> If find_vm_area() is called to reports vm area information,
> kasan can trigger deadlock like:
>
> CPU0                                CPU1
> vmalloc();
>  alloc_vmap_area();
>   spin_lock(&vn->busy.lock)
>                                     spin_lock_bh(&some_lock);
>    <interrupt occurs>
>    <in softirq>
>    spin_lock(&some_lock);
>                                     <access invalid address>
>                                     kasan_report();
>                                      print_report();
>                                       print_address_description();
>                                        kasan_find_vm_area();
>                                         find_vm_area();
>                                          spin_lock(&vn->busy.lock) // dea=
dlock!
>
> To prevent possible deadlock while kasan reports, remove kasan_find_vm_ar=
ea().
>
> Fixes: c056a364e954 ("kasan: print virtual mapping info in reports")
> Reported-by: Yunseong Kim <ysk@kzalloc.com>
> Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>

As a fix:

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

But it would be great to figure out a way to eventually restore this
functionality; I'll file a bug for this once this patch lands. The
virtual mapping info helps with real issues: e.g. just recently it
helped me to quickly see the issue that caused a false-positive report
[1].

[1] https://lore.kernel.org/all/CA+fCnZfzHOFjVo43UZK8H6h3j=3DOHjfF13oFJvT0P=
-SM84Oc4qQ@mail.gmail.com/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcMpi6sUW2ksd_r1D78D8qnKag41HNYCHz%3DHM1-DL71jg%40mail.gmail.com.
