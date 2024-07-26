Return-Path: <kasan-dev+bncBDW2JDUY5AORBV7CRO2QMGQELVMIU2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 58C7E93CC2F
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jul 2024 02:44:08 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-52f00bde29dsf798275e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2024 17:44:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721954647; cv=pass;
        d=google.com; s=arc-20160816;
        b=aUddP7aMGBKP7Ui+y/zu6+PYVff9YQMaNeiF6OdXILpsa2cyuXKpoerR11VnzLF9h6
         EM8bYzkLHmsiAV9FkpvoqIl/h2ppjGJ5uGZ5SrImoajKULmd7xSeojjRMDrCP74R3MNI
         zcCgsYsO+NivKJ50lZaqVOilL8gCmhu+aTTnpNYzu+IHku32VAbDemcniBPTXOUr5ss2
         qj+/Q1TPXIIIyIuihTgWxKf3ImqhmZ2N/ohb/u60ro2k5vSTRCHStKLhNUlJipMQqFzi
         pL1dfMoQAe4/9FlQYP99i9LLRfmA/ZUJZ454LC58jFTB3he4P8MlqjOJZ+uRAnwevkKF
         RiHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=HccjQsnPeZubPDunF6SpWaEynVikcIZhdx2Hq6QzmTQ=;
        fh=d2fIQP83nPn6SZB8ST3VaLjIDbz0naikdghj6XTfsGA=;
        b=tY6eMHm+ux8CJ80daEK/Gpiuvwnu+Jki6W1nuj58/VotlovhIDyNoRfRiyiC2cVs+4
         gO5T34T3ESTVmVCGoPxf3kxx4Lt62tKhg6kx6tTipHNhKXd2E4oTdjavkFgrgwy2qiY6
         5mXrlZvkJj2dHqQSBOXuFt8Qt12K91alWIiabtW+EMrKFWE5+khD0ZI+T9qSqLrLhFVz
         E6ZslTfzymDEslEZJCULaEJk56R0NzwMrPM4/5z/SE+usGUA5jKE9oJ4xM9pJEmeX8Mc
         B8PCm0iMgtms+mh4masnmNpied4cD18TJ9bLYBkfGNxkX3I9UrD6WN9mTbf8z2PIAxOz
         ETOQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AldAkEsX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721954647; x=1722559447; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HccjQsnPeZubPDunF6SpWaEynVikcIZhdx2Hq6QzmTQ=;
        b=HaNn8wJ7KfgjTdF4jvCnxheClxf+e87ol3SjuXolR1cWDnao5onDd3AwUWagfRWk49
         wfbfen6nhVLxcQ8aazhn6VkcplXIIEHZIb9V3jqAI/48mL5VSSpw4kQ7vLvJ+Ab+8LAd
         hD/mYKBLu/9giXCA7tqbv/pKNsyZFSOSd1afRT1I8W8C+pH0Re9Ppr+uB+eZbJlyZzRH
         BhvR88tyB8VUlKAt275yCc8EXUuRtRUW6MLfhYpx9vHtNEULwgi/i+uxahmcbxXGreah
         HrUFZSqNWOtRIxLzx57pCD+42/P4VY4q41jn/MsYNG2uN0uVOqu9J7bWboZ+H89uEdpI
         BhIg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1721954647; x=1722559447; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HccjQsnPeZubPDunF6SpWaEynVikcIZhdx2Hq6QzmTQ=;
        b=AnFNoFprmMWpgseSumxj2TWi+52LfYiXvegCLwzwMV5mdQKmU7naPaIT4lFYEWMg9B
         SsAeOYUSuJ8nzHTPx6da2y7AIiIzyv9jALJAWmLBLklpyVNFbWMaIhq3btk0EsK6hWrA
         5LzCGZ/9061gK6X9C7EjJqxS4ntUkGR7Qd8AS8oQ605eeoTKVrlTw897Ur2vgHuVM8mR
         21BzGoeNcg8EHIoyHHNkwGniK0r1nldufmsmzgX1QhBo1uV4gt0MPVXkApHvB3ma38JV
         evI2BcPiD2V4/HLyx83z7YphPtRZE+zpw5+zQfmuDM3zpF7aoLcfuZxYSSrcG4BcxBrQ
         4Mvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721954647; x=1722559447;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HccjQsnPeZubPDunF6SpWaEynVikcIZhdx2Hq6QzmTQ=;
        b=llj+8EFYlaF0ChrmBOIqPku1DFAKFVwWY+MgyGryJdFqEBJxzXBzHptTv+caLfdZ8w
         bVYGUIK/0I8gMxeTzXckJVIOUEn2uGTuahUGgSMKi3ABWT8lqm5Vuv2mZGf9n5ceGt/3
         83Yy8BHc5hnXX6pWvkPYhYb0MbO+y3r1q67wbzSK5QoBHuk1HDejkkp4/XqJCdbmAI7t
         +LhaL2iUTBCNZumOGKf0Nt89rnDhJ5NAhaKJekR5o9lcZG+eKu7xyIcPAJBdUi76Cpxw
         VM1GZBf+YlWM6fOV49qukya3LRTmOIJVWrcKNuFZ3VnkQwFNvkLyMPGnVw71vYQ51BLi
         w8jg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX0oPOFFKuUgKqAlbphfwLndMZszrncFHyMEAk+HR7QEJgMJ+k6UpVRh6yCOXUV3ZZSbwsFZ5eZy3XEFSpaHcjXZ+vbNdYCLQ==
X-Gm-Message-State: AOJu0Yxtxs5vN202PhgXwWo63DnR0xVQhressg+DZ6qIWQJByiQOyxoq
	/ir2oOEysCrTbQ0ZBJRB175IYnLF9vntkpwEcw62WH+KNX7lFHc7
X-Google-Smtp-Source: AGHT+IEWj1cuEBYwcPLq+SN8hyu8oiIupX24Pwd/3IGwHCetYWCP0wsh+fXv3j4CI1ORZYWssmO2eg==
X-Received: by 2002:a05:6512:1114:b0:52e:936e:a237 with SMTP id 2adb3069b0e04-52fd602b514mr3744075e87.16.1721954647435;
        Thu, 25 Jul 2024 17:44:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b11:b0:52f:c9e7:c51d with SMTP id
 2adb3069b0e04-52fd3f462afls793569e87.0.-pod-prod-05-eu; Thu, 25 Jul 2024
 17:44:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5KkB26CuQVNwWdHIVioiHFYNzATuJGd7komOZ0MhXISnx+byh3t1zO1Cg9Iy2/ouZc9bHECktHY8bP71SfaSh6dUjk/6MBVj+dw==
X-Received: by 2002:a05:6512:2c95:b0:52d:b226:942a with SMTP id 2adb3069b0e04-52fd5fb3533mr3107858e87.0.1721954645301;
        Thu, 25 Jul 2024 17:44:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721954645; cv=none;
        d=google.com; s=arc-20160816;
        b=l1nbnry0mldNPTfHGqSXP85Gomyv62ZZtQC/Nou7wCMWm/apcTZ5CXfRCM/osQBG7a
         LoWW1q/g9KKAsj91km9oYup9Au2nw7U2j040kB76sWfC7Ua24ptNPq2+zPuqm29FoZTK
         vWOMKkVsxYfOcQngifZ+y6FIgMn459+UY0yj8xM32lshSkbvpJN5ZYtQ+xijYl5HLNDd
         d3pu69ma12lH5HsJsxJEsrMoxezXnAmhkyLe9rjhfl7fh8xxUELqNamkktbdejAkHnHm
         6862D/2gbJ51i7edg+evtdFH2BKhjLex0UNYzlJYjqXnWjHssRDX1wnjVQQ5BHkYeSej
         gyMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=qWLLE86qSUx/Olt4aDlaYWvMRcyjVLxgebJsy4G4sv8=;
        fh=ucYlzyyuoTeXGgbfNHFEeoBBCpfFfVYQi0Exc6wCFQE=;
        b=QrrChlnJp6tWY8HglRQZ1c90Ta3vcptrQQDWt/NGiNM5Omdz3+0uRtbsluwPZEYM0r
         0Ukzr3nqevElKs0QHkWtP8P1Gds2XnZN00/8TVicTDh/1rkMpk0UFlrT84tnpBpgU7rE
         AjkCOjsUR6F/jMXQN6S6nBpL9d9Ei1zjn2O7T1smg4DhBwThPdNobLW/l7d69PQiowpt
         v9BM9ek+yi0APhR6QArxYu8wtFci39DC1Inau8WMygicgH068wYLVS5yXlzY//PyoAAk
         igDQZzWpE5GBmPmGU54CtJ+OK1L0ggEOQ8U2ZjuSj/STIq9wRxyP2E3W2P3qPANHZjg3
         0RAw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AldAkEsX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a7acadc8852si6123466b.1.2024.07.25.17.44.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 25 Jul 2024 17:44:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 5b1f17b1804b1-427ffae0b91so15227355e9.0
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2024 17:44:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU2M0WLw3uhasRZngV47MEaC5KyZcXx0rDQLzt5X/dDt6vOmG9hzU3+ZOWYdAXpfIEw4rTt141JnA2DbOm9VqQahz5cAb5U6YoB9g==
X-Received: by 2002:adf:f18b:0:b0:367:f059:4c55 with SMTP id
 ffacd0b85a97d-36b363d54demr3001273f8f.26.1721954644724; Thu, 25 Jul 2024
 17:44:04 -0700 (PDT)
MIME-Version: 1.0
References: <20240725-kasan-tsbrcu-v3-0-51c92f8f1101@google.com> <20240725-kasan-tsbrcu-v3-2-51c92f8f1101@google.com>
In-Reply-To: <20240725-kasan-tsbrcu-v3-2-51c92f8f1101@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 26 Jul 2024 02:43:53 +0200
Message-ID: <CA+fCnZc1ct_Dg7_Zw+2z-EOv_oC4occ-ru-o6-83XYQneBxpwA@mail.gmail.com>
Subject: Re: [PATCH v3 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Jann Horn <jannh@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AldAkEsX;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32f
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

On Thu, Jul 25, 2024 at 5:32=E2=80=AFPM Jann Horn <jannh@google.com> wrote:
>
> Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_RC=
U
> slabs because use-after-free is allowed within the RCU grace period by
> design.
>
> Add a SLUB debugging feature which RCU-delays every individual
> kmem_cache_free() before either actually freeing the object or handing it
> off to KASAN, and change KASAN to poison freed objects as normal when thi=
s
> option is enabled.
>
> For now I've configured Kconfig.debug to default-enable this feature in t=
he
> KASAN GENERIC and SW_TAGS modes; I'm not enabling it by default in HW_TAG=
S
> mode because I'm not sure if it might have unwanted performance degradati=
on
> effects there.
>
> Note that this is mostly useful with KASAN in the quarantine-based GENERI=
C
> mode; SLAB_TYPESAFE_BY_RCU slabs are basically always also slabs with a
> ->ctor, and KASAN's assign_tag() currently has to assign fixed tags for
> those, reducing the effectiveness of SW_TAGS/HW_TAGS mode.
> (A possible future extension of this work would be to also let SLUB call
> the ->ctor() on every allocation instead of only when the slab page is
> allocated; then tag-based modes would be able to assign new tags on every
> reallocation.)
>
> Signed-off-by: Jann Horn <jannh@google.com>

Acked-by: Andrey Konovalov <andreyknvl@gmail.com>

But see some nits below.

Thank you!

> ---
>  include/linux/kasan.h | 14 ++++++----
>  mm/Kconfig.debug      | 29 ++++++++++++++++++++
>  mm/kasan/common.c     | 13 +++++----
>  mm/kasan/kasan_test.c | 44 +++++++++++++++++++++++++++++
>  mm/slab_common.c      | 12 ++++++++
>  mm/slub.c             | 76 +++++++++++++++++++++++++++++++++++++++++++++=
------
>  6 files changed, 170 insertions(+), 18 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index ebd93c843e78..c64483d3e2bd 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -186,12 +186,15 @@ static __always_inline bool kasan_slab_pre_free(str=
uct kmem_cache *s,
>  }
>
>  bool __kasan_slab_free(struct kmem_cache *s, void *object,
> -                       unsigned long ip, bool init);
> +                       unsigned long ip, bool init, bool after_rcu_delay=
);
>  static __always_inline bool kasan_slab_free(struct kmem_cache *s,
> -                                               void *object, bool init)
> +                                               void *object, bool init,
> +                                               bool after_rcu_delay)
>  {
> -       if (kasan_enabled())
> -               return __kasan_slab_free(s, object, _RET_IP_, init);
> +       if (kasan_enabled()) {
> +               return __kasan_slab_free(s, object, _RET_IP_, init,
> +                               after_rcu_delay);
> +       }
>         return false;
>  }
>
> @@ -387,7 +390,8 @@ static inline bool kasan_slab_pre_free(struct kmem_ca=
che *s, void *object)
>         return false;
>  }
>
> -static inline bool kasan_slab_free(struct kmem_cache *s, void *object, b=
ool init)
> +static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> +                                  bool init, bool after_rcu_delay)
>  {
>         return false;
>  }
> diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
> index afc72fde0f03..0c088532f5a7 100644
> --- a/mm/Kconfig.debug
> +++ b/mm/Kconfig.debug
> @@ -70,6 +70,35 @@ config SLUB_DEBUG_ON
>           off in a kernel built with CONFIG_SLUB_DEBUG_ON by specifying
>           "slab_debug=3D-".
>
> +config SLUB_RCU_DEBUG
> +       bool "Make use-after-free detection possible in TYPESAFE_BY_RCU c=
aches"

Perhaps, it makes sense to point out that is related to KASAN's
use-after-free detection in the option description.

> +       depends on SLUB_DEBUG

Do we need depends on KASAN?

> +       default KASAN_GENERIC || KASAN_SW_TAGS
> +       help
> +         Make SLAB_TYPESAFE_BY_RCU caches behave approximately as if the=
 cache
> +         was not marked as SLAB_TYPESAFE_BY_RCU and every caller used
> +         kfree_rcu() instead.
> +
> +         This is intended for use in combination with KASAN, to enable K=
ASAN to
> +         detect use-after-free accesses in such caches.
> +         (KFENCE is able to do that independent of this flag.)
> +
> +         This might degrade performance.
> +         Unfortunately this also prevents a very specific bug pattern fr=
om
> +         triggering (insufficient checks against an object being recycle=
d
> +         within the RCU grace period); so this option can be turned off =
even on
> +         KASAN builds, in case you want to test for such a bug.
> +
> +         If you're using this for testing bugs / fuzzing and care about
> +         catching all the bugs WAY more than performance, you might want=
 to
> +         also turn on CONFIG_RCU_STRICT_GRACE_PERIOD.
> +
> +         WARNING:
> +         This is designed as a debugging feature, not a security feature=
.
> +         Objects are sometimes recycled without RCU delay under memory p=
ressure.
> +
> +         If unsure, say N.
> +
>  config PAGE_OWNER
>         bool "Track page owner"
>         depends on DEBUG_KERNEL && STACKTRACE_SUPPORT
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 7c7fc6ce7eb7..d92cb2e9189d 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -238,7 +238,8 @@ static enum free_validation_result check_slab_free(st=
ruct kmem_cache *cache,
>  }
>
>  static inline bool poison_slab_object(struct kmem_cache *cache, void *ob=
ject,
> -                                     unsigned long ip, bool init)
> +                                     unsigned long ip, bool init,
> +                                     bool after_rcu_delay)
>  {
>         void *tagged_object =3D object;
>         enum free_validation_result valid =3D check_slab_free(cache, obje=
ct, ip);
> @@ -251,7 +252,8 @@ static inline bool poison_slab_object(struct kmem_cac=
he *cache, void *object,
>         object =3D kasan_reset_tag(object);
>
>         /* RCU slabs could be legally used after free within the RCU peri=
od. */
> -       if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
> +       if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU) &&
> +           !after_rcu_delay)

This can be kept on the same line.

>                 return false;
>
>         kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_S=
IZE),
> @@ -270,7 +272,8 @@ bool __kasan_slab_pre_free(struct kmem_cache *cache, =
void *object,
>  }
>
>  bool __kasan_slab_free(struct kmem_cache *cache, void *object,
> -                               unsigned long ip, bool init)
> +                               unsigned long ip, bool init,
> +                               bool after_rcu_delay)
>  {
>         if (is_kfence_address(object))
>                 return false;
> @@ -280,7 +283,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void=
 *object,
>          * freelist. The object will thus never be allocated again and it=
s
>          * metadata will never get released.
>          */
> -       if (poison_slab_object(cache, object, ip, init))
> +       if (poison_slab_object(cache, object, ip, init, after_rcu_delay))
>                 return true;
>
>         /*
> @@ -535,7 +538,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigne=
d long ip)
>                 return false;
>
>         slab =3D folio_slab(folio);
> -       return !poison_slab_object(slab->slab_cache, ptr, ip, false);
> +       return !poison_slab_object(slab->slab_cache, ptr, ip, false, fals=
e);
>  }
>
>  void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned lo=
ng ip)
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 7b32be2a3cf0..cba782a4b072 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -996,6 +996,49 @@ static void kmem_cache_invalid_free(struct kunit *te=
st)
>         kmem_cache_destroy(cache);
>  }
>
> +static void kmem_cache_rcu_uaf(struct kunit *test)
> +{
> +       char *p;
> +       size_t size =3D 200;
> +       struct kmem_cache *cache;
> +
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB_RCU_DEBUG);
> +
> +       cache =3D kmem_cache_create("test_cache", size, 0, SLAB_TYPESAFE_=
BY_RCU,
> +                                 NULL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> +
> +       p =3D kmem_cache_alloc(cache, GFP_KERNEL);
> +       if (!p) {
> +               kunit_err(test, "Allocation failed: %s\n", __func__);
> +               kmem_cache_destroy(cache);
> +               return;
> +       }
> +       *p =3D 1;
> +
> +       rcu_read_lock();
> +
> +       /* Free the object - this will internally schedule an RCU callbac=
k. */
> +       kmem_cache_free(cache, p);
> +
> +       /* We should still be allowed to access the object at this point =
because

Empty line after /* here and below.



> +        * the cache is SLAB_TYPESAFE_BY_RCU and we've been in an RCU rea=
d-side
> +        * critical section since before the kmem_cache_free().
> +        */
> +       READ_ONCE(*p);
> +
> +       rcu_read_unlock();
> +
> +       /* Wait for the RCU callback to execute; after this, the object s=
hould
> +        * have actually been freed from KASAN's perspective.
> +        */
> +       rcu_barrier();
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
> +
> +       kmem_cache_destroy(cache);
> +}
> +
>  static void empty_cache_ctor(void *object) { }
>
>  static void kmem_cache_double_destroy(struct kunit *test)
> @@ -1937,6 +1980,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
>         KUNIT_CASE(kmem_cache_oob),
>         KUNIT_CASE(kmem_cache_double_free),
>         KUNIT_CASE(kmem_cache_invalid_free),
> +       KUNIT_CASE(kmem_cache_rcu_uaf),
>         KUNIT_CASE(kmem_cache_double_destroy),
>         KUNIT_CASE(kmem_cache_accounted),
>         KUNIT_CASE(kmem_cache_bulk),
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 1560a1546bb1..19511e34017b 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -450,6 +450,18 @@ static void slab_caches_to_rcu_destroy_workfn(struct=
 work_struct *work)
>
>  static int shutdown_cache(struct kmem_cache *s)
>  {
> +       if (IS_ENABLED(CONFIG_SLUB_RCU_DEBUG) &&
> +           (s->flags & SLAB_TYPESAFE_BY_RCU)) {
> +               /*
> +                * Under CONFIG_SLUB_RCU_DEBUG, when objects in a
> +                * SLAB_TYPESAFE_BY_RCU slab are freed, SLUB will interna=
lly
> +                * defer their freeing with call_rcu().
> +                * Wait for such call_rcu() invocations here before actua=
lly
> +                * destroying the cache.
> +                */
> +               rcu_barrier();
> +       }
> +
>         /* free asan quarantined objects */
>         kasan_cache_shutdown(s);
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 34724704c52d..f44eec209e3e 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2144,15 +2144,26 @@ static inline void memcg_slab_free_hook(struct km=
em_cache *s, struct slab *slab,
>  }
>  #endif /* CONFIG_MEMCG_KMEM */
>
> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head);
> +
> +struct rcu_delayed_free {
> +       struct rcu_head head;
> +       void *object;
> +};
> +#endif
> +
>  /*
>   * Hooks for other subsystems that check memory allocations. In a typica=
l
>   * production configuration these hooks all should produce no code at al=
l.
>   *
>   * Returns true if freeing of the object can proceed, false if its reuse
> - * was delayed by KASAN quarantine, or it was returned to KFENCE.
> + * was delayed by CONFIG_SLUB_RCU_DEBUG or KASAN quarantine, or it was r=
eturned
> + * to KFENCE.
>   */
>  static __always_inline
> -bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
> +bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
> +                   bool after_rcu_delay)
>  {
>         kmemleak_free_recursive(x, s->flags);
>         kmsan_slab_free(s, x);
> @@ -2163,7 +2174,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, =
bool init)
>                 debug_check_no_obj_freed(x, s->object_size);
>
>         /* Use KCSAN to help debug racy use-after-free. */
> -       if (!(s->flags & SLAB_TYPESAFE_BY_RCU))
> +       if (!(s->flags & SLAB_TYPESAFE_BY_RCU) || after_rcu_delay)
>                 __kcsan_check_access(x, s->object_size,
>                                      KCSAN_ACCESS_WRITE | KCSAN_ACCESS_AS=
SERT);
>
> @@ -2177,6 +2188,28 @@ bool slab_free_hook(struct kmem_cache *s, void *x,=
 bool init)
>         if (kasan_slab_pre_free(s, x))
>                 return false;
>
> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +       if ((s->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_delay) {
> +               struct rcu_delayed_free *delayed_free;
> +
> +               delayed_free =3D kmalloc(sizeof(*delayed_free), GFP_NOWAI=
T);
> +               if (delayed_free) {
> +                       /*
> +                        * Let KASAN track our call stack as a "related w=
ork
> +                        * creation", just like if the object had been fr=
eed
> +                        * normally via kfree_rcu().
> +                        * We have to do this manually because the rcu_he=
ad is
> +                        * not located inside the object.
> +                        */
> +                       kasan_record_aux_stack_noalloc(x);
> +
> +                       delayed_free->object =3D x;
> +                       call_rcu(&delayed_free->head, slab_free_after_rcu=
_debug);
> +                       return false;
> +               }
> +       }
> +#endif /* CONFIG_SLUB_RCU_DEBUG */
> +
>         /*
>          * As memory initialization might be integrated into KASAN,
>          * kasan_slab_free and initialization memset's must be
> @@ -2200,7 +2233,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, =
bool init)
>                        s->size - inuse - rsize);
>         }
>         /* KASAN might put x into memory quarantine, delaying its reuse. =
*/
> -       return !kasan_slab_free(s, x, init);
> +       return !kasan_slab_free(s, x, init, after_rcu_delay);
>  }
>
>  static __fastpath_inline
> @@ -2214,7 +2247,7 @@ bool slab_free_freelist_hook(struct kmem_cache *s, =
void **head, void **tail,
>         bool init;
>
>         if (is_kfence_address(next)) {
> -               slab_free_hook(s, next, false);
> +               slab_free_hook(s, next, false, false);
>                 return false;
>         }
>
> @@ -2229,7 +2262,7 @@ bool slab_free_freelist_hook(struct kmem_cache *s, =
void **head, void **tail,
>                 next =3D get_freepointer(s, object);
>
>                 /* If object's reuse doesn't have to be delayed */
> -               if (likely(slab_free_hook(s, object, init))) {
> +               if (likely(slab_free_hook(s, object, init, false))) {
>                         /* Move object to the new freelist */
>                         set_freepointer(s, object, *head);
>                         *head =3D object;
> @@ -4442,7 +4475,7 @@ void slab_free(struct kmem_cache *s, struct slab *s=
lab, void *object,
>         memcg_slab_free_hook(s, slab, &object, 1);
>         alloc_tagging_slab_free_hook(s, slab, &object, 1);
>
> -       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
> +       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), f=
alse)))
>                 do_slab_free(s, slab, object, object, 1, addr);
>  }
>
> @@ -4451,7 +4484,7 @@ void slab_free(struct kmem_cache *s, struct slab *s=
lab, void *object,
>  static noinline
>  void memcg_alloc_abort_single(struct kmem_cache *s, void *object)
>  {
> -       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
> +       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), f=
alse)))
>                 do_slab_free(s, virt_to_slab(object), object, object, 1, =
_RET_IP_);
>  }
>  #endif
> @@ -4470,6 +4503,33 @@ void slab_free_bulk(struct kmem_cache *s, struct s=
lab *slab, void *head,
>                 do_slab_free(s, slab, head, tail, cnt, addr);
>  }
>
> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
> +{
> +       struct rcu_delayed_free *delayed_free =3D
> +                       container_of(rcu_head, struct rcu_delayed_free, h=
ead);
> +       void *object =3D delayed_free->object;
> +       struct slab *slab =3D virt_to_slab(object);
> +       struct kmem_cache *s;
> +
> +       if (WARN_ON(is_kfence_address(rcu_head)))
> +               return;
> +
> +       /* find the object and the cache again */
> +       if (WARN_ON(!slab))
> +               return;
> +       s =3D slab->slab_cache;
> +       if (WARN_ON(!(s->flags & SLAB_TYPESAFE_BY_RCU)))
> +               return;
> +
> +       /* resume freeing */
> +       if (!slab_free_hook(s, object, slab_want_init_on_free(s), true))
> +               return;
> +       do_slab_free(s, slab, object, NULL, 1, _THIS_IP_);
> +       kfree(delayed_free);
> +}
> +#endif /* CONFIG_SLUB_RCU_DEBUG */
> +
>  #ifdef CONFIG_KASAN_GENERIC
>  void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr=
)
>  {
>
> --
> 2.45.2.1089.g2a221341d9-goog
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZc1ct_Dg7_Zw%2B2z-EOv_oC4occ-ru-o6-83XYQneBxpwA%40mail.gm=
ail.com.
