Return-Path: <kasan-dev+bncBD22BAF5REGBBOH2ZGRAMGQETF6WDMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AD766F5B11
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 17:26:49 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2ac73b73781sf4655561fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 08:26:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683127608; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZlHLBDOAQSCByBdOlCbnDnwMnBaMkRilG435pBfgnR7et1+lqobk7HP+D1VYhQGSYJ
         Do66hW55/8M09XOOH8AbF9SY98eJ11HTe0NEr7EeCxoWqLyq2irYYJuUl3gAhhEvhSFw
         SJcUlCL18jt1m7WsYPiQb2IN8qs1mxa1VZ1YybEf0T1cinluAQ2vTNGNWhg2r3EAsmE6
         2J8i/fixI/zZl81alVIxtkEi7/Ik9m3DCjF/HFrmIub7LTB3JGgQf4MiGLrFNvdQOjjB
         OsBs3jrCNMc79XmbgVpQALgulbR5QkUvtYxK3mv1MRnfzxMQFEGVv9lCawNzidUWYyuN
         5KnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=E4g6+WPesMH0CNWAuTX2jq9QNLXGbngj4mV8RDjbA/g=;
        b=UPm9jWfC+FCh2CWOoSfsCto7OzUbWqvzy9fqdkdhS/FiHf/IONe11a5lbQx2luO6uf
         YeiZT7dQuHEpt6xO+rXRBYH/+gbE8+w6OiQ7nQXjjB3a2lQ4MDwC9EvWiOWdd080Z23N
         9/m8s3lidLnzEbzGqrYo5M4BeROHCwi9tvx7HreQmldGWd0OX5VcQHNfIzAEQ2QftBQn
         ttOxGEbV9jn8oXeG1X0mCurCJb3e4OqaI0R1MEvQFd4dVxhs25/G+wzsBG2htMqTMlBF
         1+ApBiXKf0CgcbVuirFxDg+YiCFb5IKy4Rl0T4GQnIMIfoUQfGWrRpiUC0HHsECZlhIM
         MFmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jTdUSr50;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683127608; x=1685719608;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=E4g6+WPesMH0CNWAuTX2jq9QNLXGbngj4mV8RDjbA/g=;
        b=VpRHUpfpJJCLasUmocu8BTy06dYYgvhb+CCJYcPmv19vyzwSayX/QKSzEs72v+5uqS
         HyvSvMZy5oI6rdBX8yKBBj6+qKgK9wFPhLwR5/V+As9UCsZh5lCt+jfHYWxd1KUTI6Cn
         s7w5RI+5cWoJ8StqcqawGqKdL9PGYFA9PJQvdYFSjc7yZWh88MQXl76vQIoKbKVddZTJ
         JCOrFtfsljDz00DbMb9VjJFNebhWle94ACb888AQWde9aingX3ZVdQUhMMxOk7beM1+d
         BE8QjoT5KSsR9R9VYBUGPP2wk8b8rZiuA6xJgv+NQU9OccNL6iBEguHSiMpFCOVrG6E2
         sEFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683127608; x=1685719608;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=E4g6+WPesMH0CNWAuTX2jq9QNLXGbngj4mV8RDjbA/g=;
        b=eZpQfh0QTsoUE0vSBqJbEbMfaitUTeq47yqqzwEi6s+LywX8E9U0WJ6y+waJRoxgiR
         04bADtvWXZ9er1KVTnZzUCnUdW8CqJrdON+8fujIdVD6/sOtmW2HW8feY+OAouQyKnjV
         VxkDIeANfCXlBhtTtn3R10DvYvyO40Kg6dXQy2SavALDi4mDegNl5R5Of53WFgQve3Oq
         csVduDypSexxEJ+4rhDz62ydw3IgZej3Xduxp/1zYNyEDjjn73Pp1bsCzzw8PkdhWODD
         o/Hu72n8Ki8OkJU3/SsUPlCD5HRaxh6+XDrmJdKsqDASudOyex4uPzFRxqqmLZxgN+lD
         Zyng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwJeVg+D8RWOdHBvu80iw7t4/JUnCuRBle5Cts/+yN8Brct/tHR
	BDLPD51fgI+qvUEJQpkJIio=
X-Google-Smtp-Source: ACHHUZ7zGO1vO1pfHEbfbIXPWgzIGzaJQbhPf3p6etj65DXoeJhbVLfGqIgPKi/c8WC67DCgkQNZTA==
X-Received: by 2002:a2e:a316:0:b0:2a8:e480:a3bd with SMTP id l22-20020a2ea316000000b002a8e480a3bdmr123621lje.1.1683127608576;
        Wed, 03 May 2023 08:26:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b15:b0:4e8:c8b4:347a with SMTP id
 w21-20020a0565120b1500b004e8c8b4347als976097lfu.1.-pod-prod-gmail; Wed, 03
 May 2023 08:26:47 -0700 (PDT)
X-Received: by 2002:a05:6512:38c3:b0:4dd:a5ac:f0a2 with SMTP id p3-20020a05651238c300b004dda5acf0a2mr922758lft.39.1683127607202;
        Wed, 03 May 2023 08:26:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683127607; cv=none;
        d=google.com; s=arc-20160816;
        b=IRxrVmOh7RNbgl+gIUiTUmg9oJUnu2aNC8u38Q2QAPFgvNyhY0A7OVIRcseeupb9Wh
         E8cBCSUp9HTU5QwMmbLLcVwX2DDeep2UYEekx8nJIoN5nfxyAT18VLoZS1VhV8eSjhYH
         HKnKWBcmtQzbFKXMk3A/emBsJaaKxUsZTBk+/MTAhbroJdWP5PMKZ1JbkTaQ8h2HdsgF
         EeL4hSmx1lB4jM1xy1oi5fqgjpqWE1+b2ruUh0KywJm9fx//q4FM+R4rz5ZIJQ1FUqyu
         mNJAc/urioArN/z6ooKlOgMd441MoU6W87kHZGR4CCJHoBzFvoGfHwx7kMcdEkZLi5Vj
         GE7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=tuHoUrBf8pQfO0931+PEXtFBu/LMU69t1o28N9yboIY=;
        b=Vv1QTjOYUZ9AUx9tsXr/Ur7mJ5oksGkjKbWaTH+T6tdiyqW14g/0JALictdAtNvqWs
         ptFQj33WtueR0YBQude+h+mPR/XcDzlh+6USo9EcZcgHsnGqHsl7/f/xwVOy/I1QZ6jQ
         dxkwDvAtSbneeLgLur94aggL7uVh3EfwCYdHNDzOlxLDXbRa6y0HT/lEXg+5BEGg+Pk1
         aBYXfX0X3HsEk9vl0UJMkQojygVXAeLeKqxqqNPfBIQRg2JnsEoplCzwrVGA3vSb3Rof
         2f+FUAVGMSAxMJRG32fUK9AFf+f9T2J8s1oUzZNxWX+40Gph1IUNQEoLk4O2UVYlx2bH
         Sm1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jTdUSr50;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.55.52.120 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga04.intel.com (mga04.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id f43-20020a0565123b2b00b004ec6206f60esi2337885lfv.9.2023.05.03.08.26.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 May 2023 08:26:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.55.52.120 as permitted sender) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6600,9927,10699"; a="347502727"
X-IronPort-AV: E=Sophos;i="5.99,247,1677571200"; 
   d="scan'208";a="347502727"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 03 May 2023 08:26:44 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10699"; a="766174780"
X-IronPort-AV: E=Sophos;i="5.99,247,1677571200"; 
   d="scan'208";a="766174780"
Received: from hrizk-mobl.amr.corp.intel.com (HELO [10.212.127.167]) ([10.212.127.167])
  by fmsmga004-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 03 May 2023 08:26:41 -0700
Message-ID: <b8ab89e6-0456-969d-ed31-fa64be0a0fd0@intel.com>
Date: Wed, 3 May 2023 08:26:40 -0700
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH 34/40] lib: code tagging context capture support
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-35-surenb@google.com> <ZFIO3tXCbmTn53uv@dhcp22.suse.cz>
 <CAJuCfpHrZ4kWYFPvA3W9J+CmNMuOtGa_ZMXE9fOmKsPQeNt2tg@mail.gmail.com>
From: Dave Hansen <dave.hansen@intel.com>
In-Reply-To: <CAJuCfpHrZ4kWYFPvA3W9J+CmNMuOtGa_ZMXE9fOmKsPQeNt2tg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=jTdUSr50;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.55.52.120 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 5/3/23 08:18, Suren Baghdasaryan wrote:
>>> +static inline void rem_ctx(struct codetag_ctx *ctx,
>>> +                        void (*free_ctx)(struct kref *refcount))
>>> +{
>>> +     struct codetag_with_ctx *ctc = ctx->ctc;
>>> +
>>> +     spin_lock(&ctc->ctx_lock);
>> This could deadlock when allocator is called from the IRQ context.
> I see. spin_lock_irqsave() then?

Yes.  But, even better, please turn on lockdep when you are testing.  It
will find these for you.  If you're on x86, we have a set of handy-dandy
debug options that you can add to an existing config with:

	make x86_debug.config

That said, I'm as concerned as everyone else that this is all "new" code
and doesn't lean on existing tracing or things like PAGE_OWNER enough.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b8ab89e6-0456-969d-ed31-fa64be0a0fd0%40intel.com.
