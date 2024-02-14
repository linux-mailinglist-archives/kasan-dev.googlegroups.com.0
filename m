Return-Path: <kasan-dev+bncBDM4BTMC5MIBBQMLWWXAMGQE7YQGR2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id A31B6855672
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 23:59:14 +0100 (CET)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-6077ca6e1e1sf4390397b3.2
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 14:59:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707951553; cv=pass;
        d=google.com; s=arc-20160816;
        b=W/vD4NuHUuTyjffOGv++PVoOuHA2JPdxgCfgY1TV/TrTlRJyC1sQMWL5R/Qw09lLZZ
         50/oKM0caVrVjLB7tFq9ctiGZ3Ya6c4Ocxvk0yT+vdX/ojFrj6zV2ye3YzbtS3zgQ+qJ
         lL33epouaJqrdbS3gYRIJcPvn/Qv4ljtBqk+O4U7IMOKfcZTtoc7FT0XQFVn7mJ9FSTx
         3izpS7W1srVQ0aTEeplJIhrbnxJJiWVpQXsiJL3pmXj9ixuGBjRsv5RGTIjxbL/PV96F
         EVluvj++dg+m3/GjyqLxgps2LmO1NwRxTufarP7MYVJ5pFu4rRZUFHxULTpeQNIwKVxr
         MCQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=hHS0DmcdpUgd4Q7TIKtryRsg1SA98L0BgLBmgUH2OYY=;
        fh=5FdO+m8XScF82xByGtPDzOkiZ6GGUDBIlykkO45IP/E=;
        b=Eb1bMlg2FnjmBfvc4iUx6GzVvwYx0vBRqu6YkS7d8v8cj4CccF94Sh/UrqxVar6xOy
         SL5iUhVug3NrIhJ0MCT4U1rkImqzXRfqyDEKMzXXZN5luN23BWLyNl3rUdwiBMswMsB9
         pHqsJclp7iwMSzSGOw4nU9vKGZrYpO0bdYPnd3AaZVVad/3lwfZ+6TqMDXtquL1AfHns
         N+78n7ZnmBMd6m19UiHBcsSxoGebWCwdY3hb0luGnrBO2w0UNW9dScPguQA9arjYmVQz
         oFoKaGojob2+lhL/G/wK1bqK949ll+SsHDo8wgc1kXGMZyyTjVfTRS+6OI2oYcEFxQ7z
         wDUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=llIaJN9N;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=tim.c.chen@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707951553; x=1708556353; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:content-transfer-encoding
         :references:in-reply-to:date:cc:to:from:subject:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hHS0DmcdpUgd4Q7TIKtryRsg1SA98L0BgLBmgUH2OYY=;
        b=MRhDuj0NcSYra5+eXHCQXJZLJxzDug+9MnEGfaqzzzi3Ij46sMGMCzVPR5FtNvZZNj
         UXL2YJVz6BRmG9G0SGhE+tKpRgIlkfrs321eFnxQbSO4hwGOPjGXR4NW1BA/5a/56qL9
         +8Br6XbBFjoUJCfXnCFZ5Y+LbIN/zb3UyKcVdaaZwSZ4jZVAmjF1n4tPln6tqUVjhe+f
         pwYEcozIWdjn2CRGAEfCGd8Arefc1YtvyD1zsl18VbQWWdvA1hhNNnBs91eR8S5zpl5L
         vLN2bY61Te6QsEdxZlg7z3qm+wMjaO7Cy9Y1QADwx+hyXB9DHKog1G1bpfAOIn2OVg4C
         bW4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707951553; x=1708556353;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hHS0DmcdpUgd4Q7TIKtryRsg1SA98L0BgLBmgUH2OYY=;
        b=EQYxPegLreKLuUCWP+WQxILjBoANMmXisbw4RAp7sfSLPRxSkw4kKqDc55kZAxGWwF
         6kCM/GDed0yHqrg3hstpZcQC8lv/LPpq5ktBYjscV9zfI+7T91e07E8oBfecvyu+ivil
         xru/EYxIo8ykjpYEY0xfOxdAe6HX3pNkXI/LY2JXpi6InJRh8G9SO5ZYHWmrq9xe7onM
         JXop0S+kCNECoNfe4U07fJWbEbPfwGnSphGk42FmdA2AmBr7uvExSVrtSVBGoxjCmpRw
         y7hnok5Un8LTCQ/KRs3B51lywCmTRcT/LZYkbbV99jLmNA9D8xpeka6bEXJ+7pVaj3Je
         vPRg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXFiZYldHn4yxOcWb6n6Z7pRfK/9Om6bv1jYyETRwz8jQfinfwOzAyK13GJRNxZWlbZ/YV8Zra/+eKYmAZmkDYakeT1TpQ9Sg==
X-Gm-Message-State: AOJu0YyM6rOVHnh0G3TyyJyC4b9jCMwrF8N1GvEgLMZJYz7V0rdqj7mr
	pYQs4TII/dY7WSBd4Kh9vG6t5+CXxVZR+SWZfIvTRq9fV9t2wUek
X-Google-Smtp-Source: AGHT+IESPqDEv+mMeTqGtE60v77dpYPfDC64lDKVL5uPHdPCzVw1Pp8Dqybwixae1awaStspx+AOiQ==
X-Received: by 2002:a25:c752:0:b0:dc7:d6:fd44 with SMTP id w79-20020a25c752000000b00dc700d6fd44mr3706696ybe.65.1707951553198;
        Wed, 14 Feb 2024 14:59:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:e0cb:0:b0:dcc:4b24:c0da with SMTP id x194-20020a25e0cb000000b00dcc4b24c0dals3013730ybg.2.-pod-prod-02-us;
 Wed, 14 Feb 2024 14:59:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUS27bWKN1ciLUI7fTt7eCiBlzuDFaKFwyvnHcQN1RTopCeINjGEgRmE73InC6IUfvFed344a5oNGXzKdj0S9ezH3Z7SBH833ujYw==
X-Received: by 2002:a81:4910:0:b0:607:adca:996c with SMTP id w16-20020a814910000000b00607adca996cmr12895ywa.41.1707951552438;
        Wed, 14 Feb 2024 14:59:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707951552; cv=none;
        d=google.com; s=arc-20160816;
        b=o37DFl7K5ud4jTUapX2GoIsYGvOcYETyFL0DzIOSKiNKfBdWHw4iTPnY2uWzY7b/s4
         cqZy+lvkVq2H7uzoi3877wKx4WRwv1qgKCCqZOEXzS07r8sNPXZGhtBma3C15NXh/VHa
         IV0yribPgO9zG8+wOBVqd4c3x+XK36kzaVDVEwiNj+m5ejvN3CsC24faFbYoZhoucbeF
         n/T9Cn7blyTtwNVrMy1mY/OXBufdJmc3UHvcgtP+YDXBPIEsIwIWp6+Dug9NhTyTrSbB
         y4+IoXMkBTsmfohgXOBEJNAu/cAAaQqBBsdhloH6mJxpHiGDOu8FNilDfys2tONONfmT
         2JZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=fcq93C7gdofVg9DTS2SlMy7tfYdJIINLwP8jKGvNgZE=;
        fh=gdLpfyQCKH1vrd+eqED4Pf6CpUTlocj7fCgosQ00Qas=;
        b=pW8zIO4HjjS8r3SldgZqaNVWvAaA52m/Cz0kgGye+F0JxnTle+GZO1CKGniVlKzkpT
         U1+d/Px5N0UoIA7x2HRethD4DYSLl5Sw0P8RnSPvtKu6tZqzJvRt4wl2DNXexWbU9QdC
         x5rzZNoGA6iwBJBxr5oyn9fipRr3fi6mhE/+5I66MHcdhpvj/q33dMthT/KKjagmikmT
         W6cdgdDzypMurkKySfWkZ5uvlDDA+0H4m1mVKL9z3Xjch1rssyzaoUcPNFVrPCk4rKjV
         nzHkKsrJQRWASoGcM5HRt6S0lrKG0Jfr75wninDJNUFTreuFpbGM475XZm+JJmfZe02s
         Joxw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=llIaJN9N;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=tim.c.chen@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
X-Forwarded-Encrypted: i=1; AJvYcCWEVbeyZ2KKNX++Qf+TuvZQZvjuSKIK7xGX+VVVcpz509cQfS0v93RqnRg/dJW0VO/VkGWhrohJPNahvqJgj9KvZ4tl2I6Hgl2rUA==
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.18])
        by gmr-mx.google.com with ESMTPS id a76-20020a0dd84f000000b006079da1b99asi274889ywe.4.2024.02.14.14.59.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 14 Feb 2024 14:59:12 -0800 (PST)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=198.175.65.18;
X-IronPort-AV: E=McAfee;i="6600,9927,10984"; a="2143138"
X-IronPort-AV: E=Sophos;i="6.06,160,1705392000"; 
   d="scan'208";a="2143138"
Received: from fmviesa010.fm.intel.com ([10.60.135.150])
  by orvoesa110.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Feb 2024 14:59:11 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.06,160,1705392000"; 
   d="scan'208";a="3324531"
Received: from wfaimone-mobl.amr.corp.intel.com (HELO [10.209.29.231]) ([10.209.29.231])
  by fmviesa010-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 14 Feb 2024 14:59:06 -0800
Message-ID: <f4abca3f1d89d11f31b965e58a397aa6074be9d1.camel@linux.intel.com>
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
From: Tim Chen <tim.c.chen@linux.intel.com>
To: Suren Baghdasaryan <surenb@google.com>, Yosry Ahmed
 <yosryahmed@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
 vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de,  dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net,  void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com,  catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de,  mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
  nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
 muchun.song@linux.dev,  rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yuzhao@google.com,  dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com,  dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com,  jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com,  kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org,  linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
 cgroups@vger.kernel.org
Date: Wed, 14 Feb 2024 14:59:05 -0800
In-Reply-To: <CAJuCfpEbdC4k=4aeEO=YfX2tZhkdOVaehAv9Ts7S42B_bmm=Ow@mail.gmail.com>
References: <20240212213922.783301-1-surenb@google.com>
	 <4f24986587b53be3f9ece187a3105774eb27c12f.camel@linux.intel.com>
	 <CAJuCfpGnnsMFu-2i6-d=n1N89Z3cByN4N1txpTv+vcWSBrC2eg@mail.gmail.com>
	 <Zc0f7u5yCq-Iwh3A@google.com>
	 <CAJuCfpEbdC4k=4aeEO=YfX2tZhkdOVaehAv9Ts7S42B_bmm=Ow@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.44.4 (3.44.4-2.fc36)
MIME-Version: 1.0
X-Original-Sender: tim.c.chen@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=llIaJN9N;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=tim.c.chen@linux.intel.com;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=intel.com
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

On Wed, 2024-02-14 at 12:30 -0800, Suren Baghdasaryan wrote:
> On Wed, Feb 14, 2024 at 12:17=E2=80=AFPM Yosry Ahmed <yosryahmed@google.c=
om> wrote:
> >=20
> > > > > Performance overhead:
> > > > > To evaluate performance we implemented an in-kernel test executin=
g
> > > > > multiple get_free_page/free_page and kmalloc/kfree calls with all=
ocation
> > > > > sizes growing from 8 to 240 bytes with CPU frequency set to max a=
nd CPU
> > > > > affinity set to a specific CPU to minimize the noise. Below are r=
esults
> > > > > from running the test on Ubuntu 22.04.2 LTS with 6.8.0-rc1 kernel=
 on
> > > > > 56 core Intel Xeon:
> > > > >=20
> > > > >                         kmalloc                 pgalloc
> > > > > (1 baseline)            6.764s                  16.902s
> > > > > (2 default disabled)    6.793s (+0.43%)         17.007s (+0.62%)
> > > > > (3 default enabled)     7.197s (+6.40%)         23.666s (+40.02%)
> > > > > (4 runtime enabled)     7.405s (+9.48%)         23.901s (+41.41%)
> > > > > (5 memcg)               13.388s (+97.94%)       48.460s (+186.71%=
)
> > >=20
> > > (6 default disabled+memcg)    13.332s (+97.10%)         48.105s (+184=
.61%)
> > > (7 default enabled+memcg)     13.446s (+98.78%)       54.963s (+225.1=
8%)
> >=20
> > I think these numbers are very interesting for folks that already use
> > memcg. Specifically, the difference between 6 & 7, which seems to be
> > ~0.85% and ~14.25%. IIUC, this means that the extra overhead is
> > relatively much lower if someone is already using memcgs.
>=20
> Well, yes, percentage-wise it's much lower. If you look at the
> absolute difference between 6 & 7 vs 2 & 3, it's quite close.
>=20
> >=20
> > >=20
> > > (6) shows a bit better performance than (5) but it's probably noise. =
I
> > > would expect them to be roughly the same. Hope this helps.
> > >=20
> > > >=20

Thanks for the data.  It does show that turning on memcg does not cost
extra overhead percentage wise.

Tim

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f4abca3f1d89d11f31b965e58a397aa6074be9d1.camel%40linux.intel.com.
