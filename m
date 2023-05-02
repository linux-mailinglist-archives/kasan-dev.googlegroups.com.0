Return-Path: <kasan-dev+bncBCT4VV5O2QKBB26BYKRAMGQEQ6UXCXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E2A06F3CF3
	for <lists+kasan-dev@lfdr.de>; Tue,  2 May 2023 07:34:37 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3312cfa3954sf2522275ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 22:34:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683005675; cv=pass;
        d=google.com; s=arc-20160816;
        b=NNGS4xiufLZWCWxaf2halWn0GBX5Y9TnJdgyxPknFYqo7Xvit6wCphNBFXLvsFM3fM
         DvYJBgQC5VbQkhEEucxRmdsnpMhIYmTpYD5M46s3bdrA+ATVwAAqx4SeKUaWg8fyP3K7
         hgo+SpfOFSuJ9TBHQ4zLy6weqVxjg+pBMrW0hBPQvTcNrl2zt6HEQpagHULxZB65vJ8E
         CDio7KtTKdgbpjGq1lzXG9HHj3wT2VwMSdqm8pbemuBcVsiVOuo8g5/Kz9s3TA7Tp9jZ
         sm+h5tYSoJYxSfC1MagrCzHmXjg82+ixcVhRbhLqb7qDd699XQMLOUHtKCO1gdg99hEf
         AP2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=8iht6FxP/uAHtnIG6w5xmU8naj9VZafIZZSMHcdYJWM=;
        b=ZzmA2E+T4VomyZnkvh1kTMt23giHaH+52smZjiXjPg31KSXK0kcs+uDh0s5xm5Xk6f
         DkNkQlTVa8PG51JYnAT4vRpbuALDAwpI87DSk2S2Rozgr+93Aw9eNCwyrpKkHeKlKBjk
         7A9ajH9+zh964Tg8Qnsjrxhgw3MlF9FsKNWBgZ4aLoY7PPab1qD/HUHwgTdsb5Q4UXpg
         0EFC/dtc34Uhy6AShcUIsnD4+9vGLHj9nY+OEGt89YAiDiOw2sB9le79arpVN/ddLrbg
         EqmnJuH/KJMR0ORGMsnpc7zZlac48Gt9UpwgJ99TP0ZUTHzvNkbry4CKeBCUMZy2PHDB
         Bkfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=QF1HVjPT;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683005675; x=1685597675;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8iht6FxP/uAHtnIG6w5xmU8naj9VZafIZZSMHcdYJWM=;
        b=WgJuV/w4A3dcW6hPfru9b1FbLJfQJfDYuU0Ue9vzOtzWbmPUl1vGXy1tiyNzsVZpPt
         XGk/c6gR+r8aumObb+IL1Gu55NVE43yx8BO7/RFE1UHyY1eHu3GvBLEShfE6+zaCLBcT
         Y4tkmzReU/SHSk89SuvRzCmCeunGF83BzBsboGl6gq73ObfgD4UrKK2iyr6mBuTNTufj
         H+o24vcvO4LY+A5kIf69kquGhi/l0hc44X1gW7wjA9DHwFNovsJxb1DgJPZChkBDHXcP
         nZxgIbGY2NUASgBpVI8JyzvTYkyKges4hn0qai33pwEt9aQqWLIn8ih7knjXwKhjsqRH
         AEhA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683005675; x=1685597675;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8iht6FxP/uAHtnIG6w5xmU8naj9VZafIZZSMHcdYJWM=;
        b=gnIbTUwwAFW8HSUG/hCk6ibGtPbhxv5G7X/GG8m/PKp2aarFUm4/WKuoJzTe7uKqMw
         /PsAcIrkPM7FwvKAHZALEOtsCnwgpu9YHoghT/M0zzZXQDpfbKLpfPs3+/xKIIog/ywF
         VDN4UlUyJebBzSbpC3zM5kaArU9CFn04Rz3kMYun5ehND2GkC6y1DlheFnqZTwywVjUG
         XHbDIdyu21xE5CapWR9c3YMxpWHZXgo6wszHyRjftwFX/+wXm706Qcu9gzLcx9LsSOjQ
         XD2XizCcNdnHPBbymHvEgUh9qSZInuOSNZgpgW52jhi1DzEERu31iOeHmQGfRYnZLo2a
         Xjeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683005675; x=1685597675;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8iht6FxP/uAHtnIG6w5xmU8naj9VZafIZZSMHcdYJWM=;
        b=Ljih3I45UeHRu8eHXsXf5Rhe5ISrUYDfW9jAO3v4i+IPcLSmIA7SorpLQx3kGHmMj7
         OEAfX7i+THHI5ZXRPvdpBx3Ndo3cXxk7VtNvIItHFBcCoBXhsl5P0iOH7UT60fYQDLoi
         b+qQ9nsLsFrGp8USKZCke9mzJDnhi03UMN3QhUKwIjJNhJMZEoUsly2QhOg20jYiY232
         4HDvtL5ltS6XRBR3AVTJyiN8/i3pB0/4iQXdcUge1KPvCLb/0WptLJhq54w3MdcbbR1z
         VtpJx+nD36ObKITH+7EeoX9/Fn5RQ92PJyU9PP/BjCJbjUDGdAVT4J37Wh+n+tQcjBit
         kd7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyVSXLrIMARQQkuWVIkpBK275hrG4WlYz77KMaVuI/WuLQqdrbQ
	uqbI1nB4nQXH/Fa975u8uYo=
X-Google-Smtp-Source: ACHHUZ5ZC12krz6JCVyk1H8LUP4MR19aDi801/WML03mNYnowbFnsbAnUp5apLsxqCROO7DJr/h5Vg==
X-Received: by 2002:a05:6e02:806:b0:310:9fc1:a92b with SMTP id u6-20020a056e02080600b003109fc1a92bmr8096894ilm.0.1683005675638;
        Mon, 01 May 2023 22:34:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:8c3:b0:761:3f80:35c9 with SMTP id
 h3-20020a05660208c300b007613f8035c9ls2425780ioz.6.-pod-prod-gmail; Mon, 01
 May 2023 22:34:34 -0700 (PDT)
X-Received: by 2002:a5e:a70a:0:b0:763:5ead:f20b with SMTP id b10-20020a5ea70a000000b007635eadf20bmr10068244iod.16.1683005674883;
        Mon, 01 May 2023 22:34:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683005674; cv=none;
        d=google.com; s=arc-20160816;
        b=AX1ubJiMOzv9qecDwG22G+XReBMOH5ZMvIU1SO22pCBEJGD9G7hyNOUImR29LlFiin
         EUzWQDWZU/wGJX1VY/Z6XyIuey9CyeEYM2AKTYa0Bf2S8/g+J7LQlVgiPRyoI781mK4d
         KfPZTOahApDVdDADyvfmWrtbi9nFIUk8FuJJTBEZlK2bKiqoUWsoUPznKoyK9gU7yvJQ
         VsBFl2h8Geie/mm1o2Do42GSi2uS3dcttCCX8BSbHkOIayHihjqgT0k5HGtdSOUgDrqC
         4Q7As8ve7fvuAmpAIJifxHnQLvVN/QVZ5eDKNCmhvb/4dtVe9/y5HO6d28mklTeMFiRI
         Bjbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Qrcuuma9akhRKA9cVsiv9Wp3Fts3/L+OpcqEI96PfXk=;
        b=BUbNZf7v1TAjvIqc9uybqCs/tVw9SM9A4/1NgblrDqEgExQ/aPjeoeeblQIOtlQSDj
         VbjrI1IGwrNGWt5fEK0nepurcTEiGhk2NTjnA5+ovwlzIdsyEv8/KRMf9fnzsxAN0GcC
         PDaOhpsvhE4SFtxZGRfY0aR2gMA60hdJoR0PwuNiB6Qy/MpsrBH5X1Vicr2Gu8NS8jMh
         o2EKo/7p3U4epLcIePMirHgTj4GihGNa8kAzk+0sEkW/oQQJWlpLuV29Q9jA0pQsOokR
         ZHh9GYHo+GCSV+WF2AQDa09SkHN/EdHXcazLMLgC2pSXCc2pUmecB99PGwvKDL3L5U9n
         ZvXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=QF1HVjPT;
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf2a.google.com (mail-qv1-xf2a.google.com. [2607:f8b0:4864:20::f2a])
        by gmr-mx.google.com with ESMTPS id c7-20020a0566022d0700b00760fac3ba91si1588283iow.2.2023.05.01.22.34.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 22:34:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2607:f8b0:4864:20::f2a as permitted sender) client-ip=2607:f8b0:4864:20::f2a;
Received: by mail-qv1-xf2a.google.com with SMTP id 6a1803df08f44-61a62fc8b5bso19030646d6.2
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 22:34:34 -0700 (PDT)
X-Received: by 2002:a05:6214:d04:b0:56e:aeaa:95b2 with SMTP id
 4-20020a0562140d0400b0056eaeaa95b2mr3054068qvh.9.1683005674261; Mon, 01 May
 2023 22:34:34 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-2-surenb@google.com>
 <ouuidemyregstrijempvhv357ggp4tgnv6cijhasnungsovokm@jkgvyuyw2fti>
 <ZFAUj+Q+hP7cWs4w@moria.home.lan> <b6b472b65b76e95bb4c7fc7eac1ee296fdbb64fd.camel@HansenPartnership.com>
 <ZFCA2FF+9MI8LI5i@moria.home.lan>
In-Reply-To: <ZFCA2FF+9MI8LI5i@moria.home.lan>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Tue, 2 May 2023 08:33:57 +0300
Message-ID: <CAHp75VdK2bgU8P+-np7ScVWTEpLrz+muG-R15SXm=ETXnjaiZg@mail.gmail.com>
Subject: Re: [PATCH 01/40] lib/string_helpers: Drop space in string_get_size's output
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: James Bottomley <James.Bottomley@hansenpartnership.com>, 
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>, 
	=?UTF-8?B?Tm9yYWxmIFRyw6/Cv8K9bm5lcw==?= <noralf@tronnes.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andy.shevchenko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=QF1HVjPT;       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2607:f8b0:4864:20::f2a as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, May 2, 2023 at 6:18=E2=80=AFAM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
> On Mon, May 01, 2023 at 10:22:18PM -0400, James Bottomley wrote:

...

> > > If someone raises a specific objection we'll do something different,
> > > otherwise I think standardizing on what userspace tooling already
> > > parses is a good idea.
> >
> > If you want to omit the space, why not simply add your own variant?  A
> > string_get_size_nospace() which would use most of the body of this one
> > as a helper function but give its own snprintf format string at the
> > end.  It's only a couple of lines longer as a patch and has the bonus
> > that it definitely wouldn't break anything by altering an existing
> > output.
>
> I'm happy to do that - I just wanted to post this version first to see
> if we can avoid the fragmentation and do a bit of standardizing with
> how everything else seems to do that.

Actually instead of producing zillions of variants, do a %p extension
to the printf() and that's it. We have, for example, %pt with T and
with space to follow users that want one or the other variant. Same
can be done with string_get_size().

--=20
With Best Regards,
Andy Shevchenko

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHp75VdK2bgU8P%2B-np7ScVWTEpLrz%2BmuG-R15SXm%3DETXnjaiZg%40mail.=
gmail.com.
