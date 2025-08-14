Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBH7W67CAMGQER5UEG3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id DCFEEB26A6A
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 17:05:05 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-55ce5260e41sf619859e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 08:05:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755183905; cv=pass;
        d=google.com; s=arc-20240605;
        b=NaSbHs0DJto9sU26PMxGPOBOeQAt8LBSqB5juVNvSW/E6lNM67NlKJLVlc9RcXOYLK
         0rhYSUf76v6OhoaV/j46RvbiQ9jPJVdOZrMKY+tTMwLZ9dl4K4tQNAHyixoBqqdrKjtq
         79XueKG5MYk1HtA5QMTb745VWw3vaNeSQtvT/bLZHhiKFIVOzoLi0z29kilxyeZJ59YY
         ZDgZCtivi7g9hK19GeUmyuhhka3ZqvAlJqwHdMKJlHCIlSuFxwNMnD4JV+xikTOt0Vif
         43ogqF2HfsT4vLjRQqqOvull3q9XPZuvSxc+/vkeoVZVU1/BgKrJKF/bLRxkvXiQCY7g
         fBaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ozSB0EIDJn7b+Q3ZZlMuj4sQm7axKOHLQfHUMFKgWa8=;
        fh=C+BNVBU/aS6Y6xPrZb1oMvAbA/2nyOq7DTQGZUX9wvg=;
        b=AMZ4XUUExSDfO1pj2t4gaUHusBBY2p8vXVgvoUIvkp3Opf+cAOvtL1zuB9H7ZYtJpZ
         ZU7mFMzROMmQ0F0ooXWHG2CRINQLSkeKC/SBWxh579bkcSZaI8o4vej2L7y5ExFIJm3D
         /35g1U3uoFbqdVd0Mw5qRpiCw4XYSry9EkinKF8FrphVbNxqz6T/je27Yv2g81fHV0hX
         96aXPgMWX2vM6qADTyjsmHof82C0SvjfIPWzJZqSdGD2Wf66mAIRRyrodvaEknS2TjAG
         FEZBb71DlWt0sfJYZz2ctC0gcsAXUUQLo27hsSyHiSdwZHoYdLi83k4fj1Gz+4cm2pqD
         mtCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="4U0/0h3e";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755183905; x=1755788705; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ozSB0EIDJn7b+Q3ZZlMuj4sQm7axKOHLQfHUMFKgWa8=;
        b=hhnN1SEe49Kl6HN1qvGQplhjyPMNJoRRUjVaILNrjlZJarUAn/BLrOaeXQn3T/I7Vd
         T/2X6grALS8OhrNjXLsSec8C7Ch+ZHwgg5/Guz+acdW4hy0mUNuHKQzqzqYv50Z+XBip
         fzDdny+xRC4mAmHLLg+x04yTf6z3wlzt88fj2BimVM0mtmIa68oz1CRle8PYie6vUOFw
         ADC+b0QGVcdJR9HZOzH5ZZcnIvvS9+oIXT/wZuqYTa82imvxavKBEp6AmdaxxMK0BOv3
         eLnMnyTDb24LfmR8ihiFiV2Ejy0/RKRnP02NThxIfUOgYdSPZ72rhvvesKzgVZd1jGAt
         GtXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755183905; x=1755788705;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ozSB0EIDJn7b+Q3ZZlMuj4sQm7axKOHLQfHUMFKgWa8=;
        b=jxM481DPsUewbFMV6h1CH0sfOvd9ArTxHhAqXTuE/pC/RCpPSItLKY2OYDUvi0R6e7
         L/vGP49n32UrFeIDG1AFN+VR6BFqwVZMQ0IAATLnXWGKW2u4ci99fba24h28LG999z0C
         1zZwUJQMdJOWLfzPxJasPDl+IsaSDVjKHCnUxUP8enyP3Ta6hkNTPV6VkZFaT51riSDW
         AGGq7/aaiILt/g8dVHHC13EV/zlnjMOHnYqXuZ00Bsqof/AW7UziFa5ZvHqGf2yU6Xnq
         AjFSfDBm04WunICfXAF9s//PUdFUvcEqw7TuLvtHHghU5yhLkpoT/29cS/jkMewGdgxG
         ostA==
X-Forwarded-Encrypted: i=2; AJvYcCU+PiMjiiR5PHdO8g5DDKA9VBE3wKS1jUBE7k0QzZnxJ5y5sIk0mRVKLSV/WdBliaRTAponQg==@lfdr.de
X-Gm-Message-State: AOJu0YwLpPn3xhW16p7IuzX/XsPQbpTPOmC4CcMfirh35NOl7+Na87Tx
	IXtodqo2wEwbnwgJzqxUDoYxr8dMtQj+Sh09rnLbZFY1rgvT3gIg0ji+
X-Google-Smtp-Source: AGHT+IFXv99vl+58NWJUwZg9zc4bPmILkTSKjzIF4CXaiVdW4wNaUU8GOg1spoMSJxyS6X8v1ohLpA==
X-Received: by 2002:a05:6512:118e:b0:55b:9444:b165 with SMTP id 2adb3069b0e04-55ce5016b1cmr1087885e87.24.1755183904811;
        Thu, 14 Aug 2025 08:05:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZewjZ8VrTzV6aTZPK24HOeUAKu0VuTn3+IdmgljE7BOkA==
Received: by 2002:a05:6512:e9f:b0:55b:81dc:df96 with SMTP id
 2adb3069b0e04-55ce4b64ea5ls433311e87.2.-pod-prod-09-eu; Thu, 14 Aug 2025
 08:05:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXQVWeNXZJ6n4D1kiZSupg/4YBOuIU2p8KMIgNrtXO2W5X5WbgvBUBfYitvpGMxiDj3+B5cX5RxrrM=@googlegroups.com
X-Received: by 2002:a05:6512:138c:b0:553:2cc1:2bb2 with SMTP id 2adb3069b0e04-55ce4ffd208mr1270243e87.6.1755183900664;
        Thu, 14 Aug 2025 08:05:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755183900; cv=none;
        d=google.com; s=arc-20240605;
        b=UIuHfleXHqmpn+oCQrBBMfSwrHrENIyMr02rh4bzMC03v/dmm9Hf20jXHDG0p3l4oc
         /yl7LAHYZwmAW+IQw1E49xrV/D/Ri0mOZnVvyJDf/17THdw6+siuaEfvXKQ1ex6jT7GW
         dVn+9IQ7xG6B8PKocznrtf5azEvw1i05W+fL+C7ahRjsNS8y9ajJo811FIWIMpkvkisO
         nRZzqB+GTPN0iAunciqhmLIkh4LGvnnsY1hlJEiSBDbIbURKs7Zzcne0KzBM1JHmsowg
         Ki6B8t3zbbco8YB4To5Tu8FqQNZcJyZ9roJNHtjmMgXp2Vnj2JTHhp3yvmlk5tz41Z5y
         luJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DHTTqKKdq/5V0+v/JW5V+lqTYrF2enAJRrocEqjtuIQ=;
        fh=L27eU6ZEC0uipK3R0OYpJ6zeQxQt7Y25zz7D+l3hk1k=;
        b=ZoN6ybEWSkth31emRvtKS1ThxcNc49etGFtAiNHyktXQVIMlF+ehgg5lE77aSwq56X
         2OWtAN4GpgHs2a/ctwuCBmJLyvYmkyQ/ESJVhlA9S5H0IoZrAodKYPP6sKO7D1H8jDXt
         2ZTuVQQzq6W/63Nc2S+e9LJUUDALoqhALDgPnjP/58GcYaLuO8wcsHoAmFGivmGgO46N
         xMi24BfBrsGnM32DKqi/w84i6v1tADBOTIwuOHHZ7NdBJB9Cpb1PYeWvn9zqnijMrlQM
         z4XyDU9A/CHcwvyTWz8VikcW1LXusWB3KA35dZg7kZm4tEgxr0HLU0NnP6+GsLMbTF5w
         88xQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="4U0/0h3e";
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52d.google.com (mail-ed1-x52d.google.com. [2a00:1450:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b88970321si770139e87.8.2025.08.14.08.05.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Aug 2025 08:05:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as permitted sender) client-ip=2a00:1450:4864:20::52d;
Received: by mail-ed1-x52d.google.com with SMTP id 4fb4d7f45d1cf-618660b684fso10912a12.0
        for <kasan-dev@googlegroups.com>; Thu, 14 Aug 2025 08:05:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWcWYtna0Vsg4VXEnuLe4xXo9vKBHnzuBaey0Wl0PUmu2jcXmPUY2pjbh0w1xPAxl5Fzr40BJDYZBQ=@googlegroups.com
X-Gm-Gg: ASbGnctIp+U8scW82InOefB4k8UT3IvKTNxjWoblGpe1Sstjr8t9dC84m54O/Q4Azg2
	0inMKR2HODWGJ3a8mTRySzF+uB7eUDrxkTCJm/3ev/IC1A/8J20VRVJSMfpoj8QnMsnRfkJvEPZ
	H0gV/xtLvSOvmNCXHe/KmqqJVduwcgzcFMg04vmjVLPHP46kySQvUsrqslUSAFC8YWHzCH3C85f
	vrhzlVbMgnD+2Yy2TveWSbjPau38eKxUcpc8a1syTtM0oGgXgW0
X-Received: by 2002:a05:6402:b66:b0:618:527d:633d with SMTP id
 4fb4d7f45d1cf-618928d3d6amr59340a12.5.1755183899573; Thu, 14 Aug 2025
 08:04:59 -0700 (PDT)
MIME-Version: 1.0
References: <20250729-kasan-tsbrcu-noquarantine-test-v2-1-d16bd99309c9@google.com>
 <CA+fCnZeuewqXSW0ZKCMkL-Cv-0vV6HthJ_sbUFR9ZDU6PmzT-g@mail.gmail.com>
In-Reply-To: <CA+fCnZeuewqXSW0ZKCMkL-Cv-0vV6HthJ_sbUFR9ZDU6PmzT-g@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Aug 2025 17:04:23 +0200
X-Gm-Features: Ac12FXwcH9CZHsSNIO3sMGBaN83LZnV8U4fAqWyZL3Muxw72pDBQ5p_7Azu-P6E
Message-ID: <CAG48ez0OnAPbnm73a+22mpBjvGHKFGqYAA8z+XocZEHXJCcQiQ@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: add test for SLAB_TYPESAFE_BY_RCU quarantine skipping
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="4U0/0h3e";       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52d as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Thu, Aug 14, 2025 at 7:10=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
> On Tue, Jul 29, 2025 at 6:49=E2=80=AFPM Jann Horn <jannh@google.com> wrot=
e:
> > Verify that KASAN does not quarantine objects in SLAB_TYPESAFE_BY_RCU s=
labs
> > if CONFIG_SLUB_RCU_DEBUG is off.
> >
> > Signed-off-by: Jann Horn <jannh@google.com>
> > ---
> > changes in v2:
> >  - disable migration to ensure that all SLUB operations use the same
> >    percpu state (vbabka)
> >  - use EXPECT instead of ASSERT for pointer equality check so that
> >    expectation failure doesn't terminate the test with migration still
> >    disabled
> > ---
> >  mm/kasan/kasan_test_c.c | 38 ++++++++++++++++++++++++++++++++++++++
> >  1 file changed, 38 insertions(+)
> >
> > diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> > index 5f922dd38ffa..0d50402d492c 100644
> > --- a/mm/kasan/kasan_test_c.c
> > +++ b/mm/kasan/kasan_test_c.c
> > @@ -1073,6 +1073,43 @@ static void kmem_cache_rcu_uaf(struct kunit *tes=
t)
> >         kmem_cache_destroy(cache);
> >  }
> >
> > +/*
> > + * Check that SLAB_TYPESAFE_BY_RCU objects are immediately reused when
> > + * CONFIG_SLUB_RCU_DEBUG is off, and stay at the same address.
>
> Would be great to also add an explanation of why we want to test for
> this (or a reference to the related fix commit?).

Okay, I'll add a sentence here, will send v3 in a bit.

> > + */
> > +static void kmem_cache_rcu_reuse(struct kunit *test)
> > +{
> > +       char *p, *p2;
> > +       struct kmem_cache *cache;
> > +
> > +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_SLUB_RCU_DEBUG);
> > +
> > +       cache =3D kmem_cache_create("test_cache", 16, 0, SLAB_TYPESAFE_=
BY_RCU,
> > +                                 NULL);
> > +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> > +
> > +       migrate_disable();
> > +       p =3D kmem_cache_alloc(cache, GFP_KERNEL);
> > +       if (!p) {
> > +               kunit_err(test, "Allocation failed: %s\n", __func__);
> > +               goto out;
> > +       }
> > +
> > +       kmem_cache_free(cache, p);
> > +       p2 =3D kmem_cache_alloc(cache, GFP_KERNEL);
> > +       if (!p2) {
> > +               kunit_err(test, "Allocation failed: %s\n", __func__);
> > +               goto out;
> > +       }
> > +       KUNIT_EXPECT_PTR_EQ(test, p, p2);
>
> I think this might fail for the HW_TAGS mode? The location will be
> reused, but the tag will be different.

No, it's a SLAB_TYPESAFE_BY_RCU cache, so the tag can't really be
different. poison_slab_object() will bail out, and assign_tag() will
reuse the already-assigned tag.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG48ez0OnAPbnm73a%2B22mpBjvGHKFGqYAA8z%2BXocZEHXJCcQiQ%40mail.gmail.com.
