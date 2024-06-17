Return-Path: <kasan-dev+bncBDK7LR5URMGRBBUHYKZQMGQE2Y3BRZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id A05EF90B9E4
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 20:42:16 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-35dc0949675sf3048724f8f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 11:42:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718649736; cv=pass;
        d=google.com; s=arc-20160816;
        b=TCRxTu3LGHp5EVKmStqKCNeo+HGaogZ4PrDnoudrovzTSLV1hcLyQAMNoPOaY/7bU3
         Dbxsi5Y3Brv6GGuLmvQ/L69Quk3EdTuoqjaXrRMUVw+0qisYg3G5y067OZQ+JEHIyR4i
         aLCMNyvvHB15UwxvqhkkF4zOK0IrxYPX84lPh8gtxH0LTt1lYyS7jXBnzTxKAOOLUmPl
         6Xx+PdBcZ4KUXBz+ba9WqTpifPthuKxedwyW+ojfA++tZXaTUyw58sO1kDvMFv2tXN2K
         BvkqTA/lMA4yn+Bg7KGOeWrsbwGcbWDXZJ1mI0uj0ciz1BciS4IGqTa3sR3c27MAXPZn
         43dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=DeDsd7GWqafvj2bown+Xe2whvk6Ocii+iygSy0VTy24=;
        fh=dzTovP16QQ2TaA6F4LYXgHqAVi6RcUX3XE97gkZ//Rc=;
        b=RerZI5csFmDgOFiG7FsGTeGlaGE6vMpkEbXMrc7W9r+B324X+xa7q24VVRyGYxiMUM
         t6GCJvK+hj/V9e99oosZNAwBPi2gophMzKBXdTHGkn8CPLsZaeWeyHznCk1xfNcWlUH6
         9uUKAxmJxUzZa6JKQf1E6zcdcFMDvEXzl83kOH1zXc9HYqSYv9HVub+tR+gKyXtYBfUi
         zBcZ8P9UgUPsJ9S+rWWamipE8Bgum2ZE0gcdvbbcw2YI7BOMnyzPQzwVzygQ9+1wkGUX
         sF0jhzTs/IU7zVMM7ftXbvFJ/2NTcci2jMas+KxxR74G6xVngwu/+Y34KXbOh8asOV1q
         2l4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=L1u9eD2r;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718649736; x=1719254536; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DeDsd7GWqafvj2bown+Xe2whvk6Ocii+iygSy0VTy24=;
        b=CkmNYUThi6Vr0YZ59uGvuykfAGBLYnLuXzZAXbffhwFGetBcwYThVf5ZqdEXNXfrA+
         pp6DCtfnKRxtIxLMqelBJj6lfn9vztJ4LtAAUX3gO784SFHRASz8uWCgOSSDV2RhVry+
         1f/iC1Ki9fjA+2SZvEK5QoDTkzMKv5K6+ci/SWjf7VxVGSvJdrHYaYhaB9agixwixoF+
         +dW37UHGGYbdVGaGNUvBOGqHlTO8CixZJL75Em6H0wTM9BeVR73AI/RLP+E9hYXsTVFO
         nO2wvcAdRt+MiCTQyR1OAUeSGI4Dy5E8N4S2/QoqQSRhglrm3z0Lyx/5GsD/o8EzA2n5
         xlww==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1718649736; x=1719254536; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=DeDsd7GWqafvj2bown+Xe2whvk6Ocii+iygSy0VTy24=;
        b=Ij/2KFc4vL+M4Rz5KBgUrG+BEh54ZyK0FdrcX2yv5mfX03nQ5pQJkCuhIrrTLdTXMI
         goo9dETnOO4fSSkrQC4wcBxBQV9ceUUaljwfz01821AO6U83h4bPhWiO6zYSfie0xVry
         aeiAlayG0VhYSuomJHgF9E2PqBXGs09H/YaKGCCBh30sMI+s3UPDf+ycax6Z2Ig80jw0
         ZIdjGHfetz+sIauGEZfHspPZxhMwR1Nny9gVG2UYC4HARyDUy0Ex0Z/9GShYQv6dhrS7
         Dmj/IeATaarf/gFohsmHl1aUtjaIfw5ZKkU5I/QN5IoPlPh7sEpXYnm0WmFu7PyD4ljL
         8Jhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718649736; x=1719254536;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DeDsd7GWqafvj2bown+Xe2whvk6Ocii+iygSy0VTy24=;
        b=sSLfzSxYKwjJun5bHg9qysJwuTovBUoUwk0DdwEDWb3jR73Fk65hZICeJXifrTrdTz
         uosYlhk1LLHJXMB0BTtuKiwkAf1ChwIcV07SK/jmbii/nijQhH9qyroXy+bQtY0v15+d
         r2G/VPjFBJqGCjV4C7HoR255RAo4JvQYACjoSGSoKgDJNJCn3la4n46N16Jkjs1NUmTM
         kh7wg4cCogbiDRN0S5lrGBBxsRhG7g3iB4DvVmY7EAwLUSBYMLHS9WkFUZbpXuD7z5D3
         3MGVDu1/qRtxKGaLsfewbZkQF3C1/ofmTEdS8tqGhELQhfU1iW+NjMgMECXZ5E6T4DSW
         Lokg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCULwX7FyIGr+dvALVC+wm1gSNWhrExxVabLM+UDWfV2OsynOmW9XE6sdOdmSYwtqaZAwZB386t+llaFRk17utUsrq+Df9/Aug==
X-Gm-Message-State: AOJu0Yy3kg6yrLOvSQjb4aoabXXT+7nrZRuqzH1jZ6KrmprCxDIn7N8f
	/x3UP3L/4ywot8AFrTle4TVC37RqYf1kXupDmtSWpBf3i+iu7LVL
X-Google-Smtp-Source: AGHT+IGjBtVITvhUjp5ntWskFbXkw1GEzNLUu4CE55MvYQVgl79/i4HjhNk+6Aw2KflAxT0ZI/QjjA==
X-Received: by 2002:adf:f1d1:0:b0:35f:28eb:5a46 with SMTP id ffacd0b85a97d-3607a741959mr9493769f8f.10.1718649735130;
        Mon, 17 Jun 2024 11:42:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:358d:b0:423:7d5:b519 with SMTP id
 5b1f17b1804b1-42307d5b933ls14363305e9.0.-pod-prod-05-eu; Mon, 17 Jun 2024
 11:42:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW1HE3UIr2ro4TA2VVNc3Cthd/GeiNb3ou5KC2/dP0ucsKxgxmMhYorbtGLo5w0UwIDUlGy8iDF+7kPjkE9m7uiv8AZcPp7TqBVbA==
X-Received: by 2002:a05:600c:4650:b0:422:7ad4:be7c with SMTP id 5b1f17b1804b1-4230484c58dmr97601115e9.34.1718649733225;
        Mon, 17 Jun 2024 11:42:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718649733; cv=none;
        d=google.com; s=arc-20160816;
        b=jwjep8g+GX0tcTv6jyMvZJX8Ub1nWsLmWiAllmLKIPXdnptLigr/QPXAbmVaWjf3h6
         v8FJjb7fX7VjmeKh89GBRM6vsuxZm4n5vsNxQXDNP5OCPak9DegOKpCiyDOgVVOP46VI
         2pj0EYYMeJGWVwp5c8Bijr/M2Me29cZTRx8tZu/XjAZ3OMNwKTg2ujiCUV/sHkUPsIKE
         Nuo5Xd1PsI0kaFDBEEfLUb73vfqTu9G/Ar6L2xEg66Etq7TsFrCuDfK/hHaKmNSfcjqi
         eCWh+fW6YXS6MfbZsK5cadFhbilf0A/AywSH1xxreUxVNKfDf9XiSohV1gIBPvveRNLQ
         ZPtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=+jO2FlPNmcOLf+hC3upZKg3SDI4/5kwrnW8GkxW5YVg=;
        fh=rVGf9qXguRWplL42R1cBz1p7hqmQNbjJzIFy/YJtD10=;
        b=llOLtXBakr42F/n0mbCGz6MWBIyeAQ3fmC+fCFKEjsr6j+azKZhzusQeZbBOMaaJZg
         +ELbVDcYSoEI+YsiV8OwlnZceBCRrEhFf4/yALgwCj9OHycJnkIi8LRLCPaWsD7jsVQJ
         hFLWcqzO2I/DFaqXZown9X4KRFWiRQLms4b5ve7jNFO3B/+KiEMazHlfpt/6os+4AAGI
         iTsNtY/NO7GrGDxSc6/vJ+CHzv1t20QkDrQK3EqIxhep8ibQCSn4u2OvwAwSNSoP0foe
         1Jo7p7dFjuyroPoPcHR22ee5Ezxgs5TvUWpTie1ZTJy0ACNId+wfK3gyv5LRj8OBK6eI
         LoWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=L1u9eD2r;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42300f54a31si2471005e9.2.2024.06.17.11.42.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Jun 2024 11:42:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id 2adb3069b0e04-52c9034860dso5882807e87.2
        for <kasan-dev@googlegroups.com>; Mon, 17 Jun 2024 11:42:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUCB/9KqiWA+lKa6EY0AuIy/kFjFJnihljT7JWCri/JgentQqOHx94IyIZXN6NPV2NJr+Fxioi7CZCZP10VPCkAXY59hhvLKuXMvw==
X-Received: by 2002:a05:6512:549:b0:521:cc8a:46dd with SMTP id 2adb3069b0e04-52ca6e56e2dmr7855127e87.11.1718649732281;
        Mon, 17 Jun 2024 11:42:12 -0700 (PDT)
Received: from pc636 (host-185-121-47-193.sydskane.nu. [185.121.47.193])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-a6f56db6182sm540019666b.51.2024.06.17.11.42.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Jun 2024 11:42:11 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Mon, 17 Jun 2024 20:42:09 +0200
To: Vlastimil Babka <vbabka@suse.cz>
Cc: paulmck@kernel.org, "Jason A. Donenfeld" <Jason@zx2c4.com>,
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Julia Lawall <Julia.Lawall@inria.fr>, linux-block@vger.kernel.org,
	kernel-janitors@vger.kernel.org, bridge@lists.linux.dev,
	linux-trace-kernel@vger.kernel.org,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	kvm@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Nicholas Piggin <npiggin@gmail.com>, netdev@vger.kernel.org,
	wireguard@lists.zx2c4.com, linux-kernel@vger.kernel.org,
	ecryptfs@vger.kernel.org, Neil Brown <neilb@suse.de>,
	Olga Kornievskaia <kolga@netapp.com>, Dai Ngo <Dai.Ngo@oracle.com>,
	Tom Talpey <tom@talpey.com>, linux-nfs@vger.kernel.org,
	linux-can@vger.kernel.org, Lai Jiangshan <jiangshanlai@gmail.com>,
	netfilter-devel@vger.kernel.org, coreteam@netfilter.org,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 00/14] replace call_rcu by kfree_rcu for simple
 kmem_cache_free callback
Message-ID: <ZnCDgdg1EH6V7w5d@pc636>
References: <20240609082726.32742-1-Julia.Lawall@inria.fr>
 <20240612143305.451abf58@kernel.org>
 <baee4d58-17b4-4918-8e45-4d8068a23e8c@paulmck-laptop>
 <Zmov7ZaL-54T9GiM@zx2c4.com>
 <Zmo9-YGraiCj5-MI@zx2c4.com>
 <08ee7eb2-8d08-4f1f-9c46-495a544b8c0e@paulmck-laptop>
 <Zmrkkel0Fo4_g75a@zx2c4.com>
 <e926e3c6-05ce-4ba6-9e2e-e5f3b37bcc23@suse.cz>
 <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
 <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=L1u9eD2r;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::131 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Jun 17, 2024 at 07:23:36PM +0200, Vlastimil Babka wrote:
> On 6/17/24 6:12 PM, Paul E. McKenney wrote:
> > On Mon, Jun 17, 2024 at 05:10:50PM +0200, Vlastimil Babka wrote:
> >> On 6/13/24 2:22 PM, Jason A. Donenfeld wrote:
> >> > On Wed, Jun 12, 2024 at 08:38:02PM -0700, Paul E. McKenney wrote:
> >> >> o	Make the current kmem_cache_destroy() asynchronously wait for
> >> >> 	all memory to be returned, then complete the destruction.
> >> >> 	(This gets rid of a valuable debugging technique because
> >> >> 	in normal use, it is a bug to attempt to destroy a kmem_cache
> >> >> 	that has objects still allocated.)
> >> 
> >> This seems like the best option to me. As Jason already said, the debugging
> >> technique is not affected significantly, if the warning just occurs
> >> asynchronously later. The module can be already unloaded at that point, as
> >> the leak is never checked programatically anyway to control further
> >> execution, it's just a splat in dmesg.
> > 
> > Works for me!
> 
> Great. So this is how a prototype could look like, hopefully? The kunit test
> does generate the splat for me, which should be because the rcu_barrier() in
> the implementation (marked to be replaced with the real thing) is really
> insufficient. Note the test itself passes as this kind of error isn't wired
> up properly.
> 
> Another thing to resolve is the marked comment about kasan_shutdown() with
> potential kfree_rcu()'s in flight.
> 
> Also you need CONFIG_SLUB_DEBUG enabled otherwise node_nr_slabs() is a no-op
> and it might fail to notice the pending slabs. This will need to change.
> 
> ----8<----
> diff --git a/lib/slub_kunit.c b/lib/slub_kunit.c
> index e6667a28c014..e3e4d0ca40b7 100644
> --- a/lib/slub_kunit.c
> +++ b/lib/slub_kunit.c
> @@ -5,6 +5,7 @@
>  #include <linux/slab.h>
>  #include <linux/module.h>
>  #include <linux/kernel.h>
> +#include <linux/rcupdate.h>
>  #include "../mm/slab.h"
>  
>  static struct kunit_resource resource;
> @@ -157,6 +158,26 @@ static void test_kmalloc_redzone_access(struct kunit *test)
>  	kmem_cache_destroy(s);
>  }
>  
> +struct test_kfree_rcu_struct {
> +	struct rcu_head rcu;
> +};
> +
> +static void test_kfree_rcu(struct kunit *test)
> +{
> +	struct kmem_cache *s = test_kmem_cache_create("TestSlub_kfree_rcu",
> +				sizeof(struct test_kfree_rcu_struct),
> +				SLAB_NO_MERGE);
> +	struct test_kfree_rcu_struct *p = kmem_cache_alloc(s, GFP_KERNEL);
> +
> +	kasan_disable_current();
> +
> +	KUNIT_EXPECT_EQ(test, 0, slab_errors);
> +
> +	kasan_enable_current();
> +	kfree_rcu(p, rcu);
> +	kmem_cache_destroy(s);
> +}
> +
>  static int test_init(struct kunit *test)
>  {
>  	slab_errors = 0;
> @@ -177,6 +198,7 @@ static struct kunit_case test_cases[] = {
>  
>  	KUNIT_CASE(test_clobber_redzone_free),
>  	KUNIT_CASE(test_kmalloc_redzone_access),
> +	KUNIT_CASE(test_kfree_rcu),
>  	{}
>  };
>  
> diff --git a/mm/slab.h b/mm/slab.h
> index b16e63191578..a0295600af92 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -277,6 +277,8 @@ struct kmem_cache {
>  	unsigned int red_left_pad;	/* Left redzone padding size */
>  	const char *name;		/* Name (only for display!) */
>  	struct list_head list;		/* List of slab caches */
> +	struct work_struct async_destroy_work;
> +
>  #ifdef CONFIG_SYSFS
>  	struct kobject kobj;		/* For sysfs */
>  #endif
> @@ -474,7 +476,7 @@ static inline bool is_kmalloc_cache(struct kmem_cache *s)
>  			      SLAB_NO_USER_FLAGS)
>  
>  bool __kmem_cache_empty(struct kmem_cache *);
> -int __kmem_cache_shutdown(struct kmem_cache *);
> +int __kmem_cache_shutdown(struct kmem_cache *, bool);
>  void __kmem_cache_release(struct kmem_cache *);
>  int __kmem_cache_shrink(struct kmem_cache *);
>  void slab_kmem_cache_release(struct kmem_cache *);
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 5b1f996bed06..c5c356d0235d 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -44,6 +44,8 @@ static LIST_HEAD(slab_caches_to_rcu_destroy);
>  static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work);
>  static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
>  		    slab_caches_to_rcu_destroy_workfn);
> +static void kmem_cache_kfree_rcu_destroy_workfn(struct work_struct *work);
> +
>  
>  /*
>   * Set of flags that will prevent slab merging
> @@ -234,6 +236,7 @@ static struct kmem_cache *create_cache(const char *name,
>  
>  	s->refcount = 1;
>  	list_add(&s->list, &slab_caches);
> +	INIT_WORK(&s->async_destroy_work, kmem_cache_kfree_rcu_destroy_workfn);
>  	return s;
>  
>  out_free_cache:
> @@ -449,12 +452,16 @@ static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
>  	}
>  }
>  
> -static int shutdown_cache(struct kmem_cache *s)
> +static int shutdown_cache(struct kmem_cache *s, bool warn_inuse)
>  {
>  	/* free asan quarantined objects */
> +	/*
> +	 * XXX: is it ok to call this multiple times? and what happens with a
> +	 * kfree_rcu() in flight that finishes after or in parallel with this?
> +	 */
>  	kasan_cache_shutdown(s);
>  
> -	if (__kmem_cache_shutdown(s) != 0)
> +	if (__kmem_cache_shutdown(s, warn_inuse) != 0)
>  		return -EBUSY;
>  
>  	list_del(&s->list);
> @@ -477,6 +484,32 @@ void slab_kmem_cache_release(struct kmem_cache *s)
>  	kmem_cache_free(kmem_cache, s);
>  }
>  
> +static void kmem_cache_kfree_rcu_destroy_workfn(struct work_struct *work)
> +{
> +	struct kmem_cache *s;
> +	int err = -EBUSY;
> +	bool rcu_set;
> +
> +	s = container_of(work, struct kmem_cache, async_destroy_work);
> +
> +	// XXX use the real kmem_cache_free_barrier() or similar thing here
It implies that we need to introduce kfree_rcu_barrier(), a new API, which i
wanted to avoid initially. Since you do it asynchronous can we just repeat
and wait until it a cache is furry freed?

I am asking because inventing a new kfree_rcu_barrier() might not be so
straight forward.

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZnCDgdg1EH6V7w5d%40pc636.
