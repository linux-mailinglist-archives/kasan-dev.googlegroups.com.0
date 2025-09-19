Return-Path: <kasan-dev+bncBCCMH5WKTMGRB77CWXDAMGQEV2PL3YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 31C41B8A2DD
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 17:06:41 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-26776d064e7sf28477435ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 08:06:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758294399; cv=pass;
        d=google.com; s=arc-20240605;
        b=l1f/SO3JFRPwQdLOrDc/TQcNgLHEzQQCOZVW8DjnWZYkIucENAosEQsF8hMuj2JHVX
         IJ1VK0cXzeSWiwP4w2YfstvanjvOxhng+kxIizm6OlAF//UX74fpbEYrHMd4xgcaXdOS
         2/uOg/gjy3ViiNW0NCQ25c1O+KLOPYLR89XYkDe9TkzOt0l2EL4rbHfWTr/QDYCv21oF
         jXfH3CLGUVnJK9rtI/3E2DpWaGid5cNwNTJaTXKkFYaKlGKxnwzIBs5Y1Bnw2B/Nno8W
         lKxM0eVE5PuDE0HbwmQFPGklTH6wBWndG8zAdQEiBzAJyGwxZ6RVDaUJO+PlQ9BicSoL
         7ZYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IardnYfs0XW5ZZYZP/02IUTkgo8Z1Y3XY4zQoV3Dzec=;
        fh=flaL1bf+rKUQ8wJZmo6OmIm0kE4Jwb3QBK6+8VGLOhs=;
        b=DHFo7cTX2oS91On7CVVwLacsseJ9JTnG70/bJ8LjpfjpnYOqaJoGv4OvA+IPr+RXEy
         IGzgQnqinlAqqIIQd/Mj4ax+kuGuqX4/278JcM4bgBgSlR61p5B04bS71VlvOUvRPPzc
         j13pDOIsO4SuJPscMHNwq8vuP1FKoAol0ctkwU484LQJWllWEh9QFlyOZVYZN9v3ZBn6
         Oupv0zAjk4ZAZANersT+oqp+usnv07bB46W9nIhwQ2AwliS+iFNoCVOOpa5npfy0NW+b
         7EhpDrt0EjOC1Z56CvbEph8mhSiQqxpcNRqNqdvIMt80A6Z+oByMT2qG4vcrBV24YWqE
         y2RQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DdltOvxG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758294399; x=1758899199; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=IardnYfs0XW5ZZYZP/02IUTkgo8Z1Y3XY4zQoV3Dzec=;
        b=FHdyQtQdyw1tURW7JH/3BFEKDwlOI8BX+SEaiR9ksOzCxaboLJPfChy+PmOdMkD900
         n+HnZSNf3EoL37h8PZrjV5Eglyn9eJH8XEhcrFLv274WQoUqPg0nBvqVCUX7F090E09X
         cHpAwBWYo1KlqqUaAP/nq2L7ErBfjutv9NgG+ApP/rvDdV6haPBqLEOLU52rzn8j8vTC
         N4GEhhYArOaxagZJo6TlWviwfnMh97NpyHtGMvimH95QTD6C2nlmJMFtOmq2T4t330fJ
         Di5GmZ1cT0ckAcFap7D6W/x6nLkWcTWUMUu0VyBTXwKrbktVZXyvaZTeVb0f6BpMYdH3
         j2hQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758294399; x=1758899199;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=IardnYfs0XW5ZZYZP/02IUTkgo8Z1Y3XY4zQoV3Dzec=;
        b=Nos3g7GNhSaxsmSYEbxCYIIdtbG/RuN2/VWIktrz5n+eoyctWjEhFKataEXAF8aRrl
         Z+oYKzWhiQvTw2sntWeONMRgefj4Ed6YyAaq81/Ahxh1n7QSA9jx6EEobvWMX5SVH9KL
         H+Al45GPU5SXyZVAQ5cVEcFN7Xq/g3MY5bhtOPQeqWeMu1W/kYAhfCt9DKywZSHiU5r+
         NNeuahQKpPeVJaePEzfio/OCJeJfP8QCNUKur6xMGlSre2FVHCyu3StCINW64GDJCFsx
         QmCLooPxPM4eHLYjmNw1Hjt9HV7+/0+EYL+kwZ70AvLRNxttp7yTP4FGIAENM8WIFH2S
         jhkg==
X-Forwarded-Encrypted: i=2; AJvYcCVvAnKYNfHWqjyFPebnckfrg3hNsXAhhP8ioY2oqyJP9PQjid5Gay3UXuqta0hWsSUg0ki80g==@lfdr.de
X-Gm-Message-State: AOJu0YwGPFjS1XC0b+QzLhgCBVquqt7d0Wy5OwEVLlSI3TKiahQEWEkP
	eH3rDxOiz6YOHAkB2ZNe20WVvxyrHxtd9uFnzvVcvjzai1BMZShlTH6s
X-Google-Smtp-Source: AGHT+IGpDpkCf0eYS57WqQ5mIvQt/FZkfyzUvjavVx2FQ6+2sd4gweKQVpnwBX5+o66gDQ6BVuufrg==
X-Received: by 2002:a17:902:f64e:b0:246:80ef:87fc with SMTP id d9443c01a7336-269ba563fb1mr59142215ad.45.1758294399390;
        Fri, 19 Sep 2025 08:06:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7pcjemuNtqZ4OADSn2Pid3VKQ5TNPCC63iXMmJSPwbiA==
Received: by 2002:a17:903:3508:b0:267:ac34:9e67 with SMTP id
 d9443c01a7336-269840f261dls24097105ad.2.-pod-prod-07-us; Fri, 19 Sep 2025
 08:06:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW0dsHpnEWBMPLSP36QGjjs7+n4vVaR8GYKULGZkvcu0zynvcLVDh2AsIxGliAew7VgVfOiYZBV8cY=@googlegroups.com
X-Received: by 2002:a17:902:d2d2:b0:25c:e4ab:c424 with SMTP id d9443c01a7336-269ba534e05mr61574895ad.33.1758294397897;
        Fri, 19 Sep 2025 08:06:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758294397; cv=none;
        d=google.com; s=arc-20240605;
        b=XOptob63G1JiaZSGq62s3bPmHwIyVVRoVaHlHdxClHLCyyfXrHn48gxLM1aan8WqDG
         2jHFyykwWkT5U4nD89Woe8FpLJ0vt0GfNwY15AbMZ9VAwj/1l5gVEh+ZLZGtbYbEiRdO
         +HAs6FzFnMzx3hkXytRikNRuR+2qA9Ix4Lpj6Rc3pE6PGy7Lv7+6C2nMheHQ7ggZH1WL
         Qi5c9By63RdGgz892fHUdsDyusLK9GQKEea0TtRqVxNvv+d1JB5fGPYrz8cl/UZG//a0
         p+4Hr7jxIFj/YnyiA4OxtoCnFkq9FcjW/GyrCYbEWUC0nY2N8zvqXGua98L6jd5RIDh7
         ftZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wq2abhQipyX+QwuDbNp6dgczc/zpKuyCE998M/az7IY=;
        fh=t7KEhyniWCZ3FoCJW1l+UvYoBCq8mgDdzldQBlyteqE=;
        b=aVVkT84xdUx5YCsuXcaTZchLSXfEYgXTgwSXXYuSpEWo0xJgs/RWlAbRciQKXhwsdH
         9pKP3YQXPXFAsczOWnFrginbIoNEyiHyoRPpC/egV0EzwzBTjW3dUcQtm37038us6ock
         mZHWvj69rJzrE5YSzeIrIXbivqxyAVYR9KGeB++x6Q9L0Ebh2RiWDE/KG/RFpv8zJoWN
         fC3JGezqEE4XlALvWHSsxegE6vqh+wJXBRd3Vo8H0ww3w8NG6i//VhUB8mKN29iR57j/
         5+ZnN1jE60Yr3nSigfWWpdIwoB7umcqYEsJuQyR8Ygk8Cw0BWj24b7bwAF/mfZoRqwHq
         ShRA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DdltOvxG;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x835.google.com (mail-qt1-x835.google.com. [2607:f8b0:4864:20::835])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-269802139c1si2378135ad.3.2025.09.19.08.06.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 08:06:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as permitted sender) client-ip=2607:f8b0:4864:20::835;
Received: by mail-qt1-x835.google.com with SMTP id d75a77b69052e-4b79773a389so22981581cf.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 08:06:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU2Oad+NH4shNGDGn7tC6wataSx4G97KuxHgDbOHNlbkw9S1hu2ZSW+OQWvIMA3PQzvEJmJJUhCLb0=@googlegroups.com
X-Gm-Gg: ASbGnctKWLLFYzitw+IqxqPIo0SO4qZ+/KpIYC34FLtvjKS8U7wzrepE2jS0LmnZymf
	HbEe/N/qzFgqLCFCUQiDhWtAiEpzqHRhxJwVr/3wze/c30JBiFySn5pareN7cXgbi5CFQUu4Hau
	0kZ/vigX+Yo8GwHDqB6Y8pvc2dujHrPg22ci4K7IPH0SVK6RCLd6pBYDuv5zWgc9N4GOhQhcL/0
	PREd/l3rZTPU9lvQWGZTBCGOlfNnFd4gpqDLQ==
X-Received: by 2002:a05:6214:212c:b0:798:acd7:2bb with SMTP id
 6a1803df08f44-7991d54f750mr32395906d6.51.1758294396642; Fri, 19 Sep 2025
 08:06:36 -0700 (PDT)
MIME-Version: 1.0
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com> <20250919145750.3448393-5-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250919145750.3448393-5-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Sep 2025 17:05:59 +0200
X-Gm-Features: AS18NWA5Hk_dVmA1agOSIAGh1dzuifFPUnlHCTY8eojJWXc2mgupvfI9rEJhlqQ
Message-ID: <CAG_fn=VXNBH-1QDAy+xR_ubUr0rZxmPBpFWov1y+7a65-mtGmA@mail.gmail.com>
Subject: Re: [PATCH v2 04/10] tools: add kfuzztest-bridge utility
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	sj@kernel.org, tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=DdltOvxG;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::835 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Sep 19, 2025 at 4:58=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Introduce the kfuzztest-bridge tool, a userspace utility for sending
> structured inputs to KFuzzTest harnesses via debugfs.
>
> The bridge takes a textual description of the expected input format, a
> file containing random bytes, and the name of the target fuzz test. It
> parses the description, encodes the random data into the binary format
> expected by the kernel, and writes the result to the corresponding
> debugfs entry.
>
> This allows for both simple manual testing and integration with
> userspace fuzzing engines. For example, it can be used for smoke testing
> by providing data from /dev/urandom, or act as a bridge for blob-based
> fuzzers (e.g., AFL) to target KFuzzTest harnesses.
>
> Signed-off-by: Ethan Graham <ethangraham@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DVXNBH-1QDAy%2BxR_ubUr0rZxmPBpFWov1y%2B7a65-mtGmA%40mail.gmail.com.
