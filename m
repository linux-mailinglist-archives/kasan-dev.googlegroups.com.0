Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBXMGT3CQMGQEE2BMGSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id E6A3DB305C7
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:36:47 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-b47173a00e8sf1074526a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:36:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755808606; cv=pass;
        d=google.com; s=arc-20240605;
        b=kjyr1Ha7Kcm95lIvJ9DErBvtfHsNLgqk09RnlfHHX2g+8klOzP+fVLUusdJ+fzGxWb
         bOjjwvCgw8NwD//K9WZ8hskCo1dlt97lZPXZwsj6h7WtXJk7aQZJP+yzIdUFhRSddJwk
         Cq+fk5BlflO8miuQke/kq/zt4y1LXyHX4NKdVFcF3/cicppYRPQjERmFEDEZtGtWBxXO
         LLy1pKECPPZM6qhW4cLwuF0jUcLTpO4edX6nkhlRp5cGN+CcwOAWU3zCE1YTsCobtf9R
         RpwXpxBpwQZSgyYr83e5hSxb9zYXNwZYKHuGbOEEHYPBvDigKPFTqllgmLqVuojDkwVm
         9omA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=sDqFjNdFV+C+f8EDpnE4MqXVXIvobfZW0JR31LmYr28=;
        fh=XAZRt8KoCzJwO1bRt2aMvzU08vJYguzGMZSwHysL30U=;
        b=SGHf0r4YDjCNT+fgoHRwRaWfhBmxVDmrZveAkoAcxo0Q4ioyZxjyf3Hw9vo+NNqu2U
         Z2mhuZ7gc2wlF+CA0UB2BRmhNOTuly00QvxWydURTtF+5JmGlgazmU8N/pe65qcenSoO
         iuM3qA8/SBC7wuzkt0XaCOXNDdsnjH+nnm9mUTBvITMvS5Wp3PtIsDjDpms3yttYTqBf
         dzrsms1rkO7kk12aW99GEg5AY+y5Q0+ifGg7R7bV8yl393HsK/edeLhF0M+6Zc24Wlfn
         IEaD4/21FHPJQe7ndAWapoYKk5kNfM1MtB1FyoV/2/uytFbwCzlZbWs3Zx96qeZ/twem
         Xkdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b="S/9ips/0";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755808606; x=1756413406; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sDqFjNdFV+C+f8EDpnE4MqXVXIvobfZW0JR31LmYr28=;
        b=HGHIDmwMlOY7MUrDes7aIF+tbmNGKNjtaFHsGFTkjcQKxfUlKkgIppZdxKzfu1EZcj
         D+NSzhB+C2mspIKvWa4smYTzG5uRRAjRjpykT8lO0CXSgnMeqE+4SFnoo2TvxuZA1Ldo
         nJ/U+7AEx2gzq2zZX1YflMciMK5o82rAHfqVkzSe8bhO1TU1YlYxZ9jIiWaQJVfCTXZX
         ECnS7JxElybn1FBxrh17tcjyAt7EjeQlaAIZRCm7LZZBKJIgb232ExpujAkTOH/eaeo1
         drz51a+zYacU0QHSpgbXiGEReTbaMkMR18ZccqZvHimBzAxMZSwqUWnyJfTAfSTIvXNS
         /mMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755808606; x=1756413406;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sDqFjNdFV+C+f8EDpnE4MqXVXIvobfZW0JR31LmYr28=;
        b=rAS6jF9w1KE43SYWIWLjYS7hrLOjh/YijaLNgWaH0tyCTb1WXjmpHGzWUoZ5B0IU/q
         Zz3DHLwI/ae8PsQijpEXWWVAjtrf4wHoB2RYsPUpv7AYYCfoBDhIYSRjmom1gJ9baQkP
         fGozBkYQsb3yEKHRK4x1gnIqisj9bbupMve7zkXiwrr24p4VbGBcxigxtN9Vt0xn2fWs
         TypMjPXiiNG8UPNhwLCon/zhb0+mOFd6SdXzevGtKzVyQ+70/mYmkjp+rGcm67g3MdCA
         WbJIw4SrfEPTwJ1Nyu8jc4I9cPg+j9FmB7Yg5taAxDiKpSNVUpj5KgiocpGDs0USqFX4
         yjLQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzkolm0aQd04p1sVbMTFrgMUVRxZYuJRysdFPFyAIILZ/NxSdXR4DQ4OUBUqYXNaGk6VRFoQ==@lfdr.de
X-Gm-Message-State: AOJu0YyB16NG3RHfpeuXjjZK2qYr04kROfEF69nZVfbwbK3qtqp9byVO
	lbsBfrqSHSC35EOjO62KpWF+YZ6XRoGgX/eAg2GB3sc90aRM3mGOyVFM
X-Google-Smtp-Source: AGHT+IE4KexH5s26afozJ86gtAUzr/h5FKFk78hcKZzMIH0ZnlzTGpHip3lr9xt0AIR5JIAihD76Ew==
X-Received: by 2002:a05:6a20:431c:b0:240:2320:abb1 with SMTP id adf61e73a8af0-24340d2c29cmr623749637.35.1755808606263;
        Thu, 21 Aug 2025 13:36:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdAC63BbkQu1YKE04rW4+lWY/GASkKhYo+YyKP2nR322A==
Received: by 2002:a17:90b:3c11:b0:31e:f73d:d1a4 with SMTP id
 98e67ed59e1d1-324eb8191d0ls1546058a91.1.-pod-prod-09-us; Thu, 21 Aug 2025
 13:36:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2dSn3sny9LEHQCEocFRcmSItQhh1AWR1o+uOJFDwudilDQRPw3bR4YOl4xHOik59yyoTBJYIpGlo=@googlegroups.com
X-Received: by 2002:a17:90b:55c7:b0:321:1680:e056 with SMTP id 98e67ed59e1d1-32515e36b50mr993194a91.9.1755808604574;
        Thu, 21 Aug 2025 13:36:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755808604; cv=none;
        d=google.com; s=arc-20240605;
        b=E7smF1+JK0HIU4/jaPBS0tYWCFtg0t7+/mEv+VmeuQYe86OyuL81S3oLJXJewSNnI5
         V6abrm/cvXm/3fhCi2A+5D0rQKG9ChlHMq9/7lSFh31oX5F23vxCsn3tJAKtJFmge5KP
         nGO3SwJGhRL8AyJFgjUXXMBISN8iqscj6jNupVUrjv8LKxFp1ZVqeFHaEQHxMgvrv1uR
         sZHolw60e/FroJiwxoud24pQYLOcRTFvISDFrRkca2gMixpHeASClmSL6wcPEBpwkX25
         sUDbReQjArDNiLHFdR4gW28Oj1wvnvLQxtjgbk7LQy+sKQMeChx36e0zzp3PNOS7Br12
         632w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=083PuN2wICwWm8iwB5WBlP6qyKXLyqdZEBdZ0ztp8l8=;
        fh=2IvqseRYzEEdYk1nCcBTZjsBe6+9AOXfLazyo/VFLP4=;
        b=H+uCV1AO0d6VDHlJR6WG1EyNxmew2+BUltdyhwoAZyHCQ0BLSB6AP+evUPWbPFpZqf
         J5169Wh30sVbndMXVyAlSvzpEt/IEI1KkBjTPd/0yRQVSV0kbqHLhZhQYA3CzTUygtyQ
         w7JBeJ+6Rc8OuyG4NQPDppawMGiw9u8+FCQp0977ZewdaQ2McR0M1vqmtEdfdB1risrc
         YRsEOC6ieib6NlrV+/9jcIHq5+27zh3F2a+wqKfEImM6y7DWsWGcyzEV0UtXYUqteGwM
         frptN4dPF8rZv/apOsVN8aoE26D+9pp34WZFFJk876ue8HQsmT1tOaKk864iT59n/pnv
         paUw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b="S/9ips/0";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-325123dfd27si41836a91.1.2025.08.21.13.36.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:36:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-e933af9f8b5so1158482276.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:36:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXCG7Qy5eD5Nq/OShVHzPW7VXH4anxnKJi2y8SpwJcDJsKhJEE+hoMuLg0IuO1TGm6AaGUT/GF90is=@googlegroups.com
X-Gm-Gg: ASbGncsCZgbBSGfq813eaRpg4iCLW7oDkJgYQ+bnDjrhBB1AS+ykBERVo/o+uW1Wl2V
	1hz2Et+Wt8auDVR5J3a8OfHPvPRJysP8a5zH5FztjHvb8QJhwwHP3H6P3GdUx/KjlYzXVHyQ7/j
	w7WfL3z4uWORXljHcbx7YP+0fLx+9llm3ftaFZg5nYRQldwA6WPw/skN4UdA0Y5cPF5BxzsuX0o
	O0X8Y8aZIO3qQB9rO2Kh74M1wo=
X-Received: by 2002:a05:6902:4381:b0:e94:dea:b80b with SMTP id
 3f1490d57ef6-e951c365621mr715984276.40.1755808604080; Thu, 21 Aug 2025
 13:36:44 -0700 (PDT)
MIME-Version: 1.0
References: <20250821200701.1329277-1-david@redhat.com> <20250821200701.1329277-32-david@redhat.com>
 <CAHk-=wjGzyGPgqKDNXM6_2Puf7OJ+DQAXMg5NgtSASN8De1roQ@mail.gmail.com> <2926d7d9-b44e-40c0-b05d-8c42e99c511d@redhat.com>
In-Reply-To: <2926d7d9-b44e-40c0-b05d-8c42e99c511d@redhat.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 21 Aug 2025 16:36:32 -0400
X-Gm-Features: Ac12FXz8i_O0Dca-zCdGNOyRYVeCyfB9Z0ucQ3KoLazk0PNM2PIB2a_qe1sXKks
Message-ID: <CAADWXX81Y3ny6WvDN8EeYvBPa2qy10PKhWfZpj=VBcqczL6npg@mail.gmail.com>
Subject: Re: [PATCH RFC 31/35] crypto: remove nth_page() usage within SG entry
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Herbert Xu <herbert@gondor.apana.org.au>, 
	"David S. Miller" <davem@davemloft.net>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Brendan Jackman <jackmanb@google.com>, 
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org, 
	iommu@lists.linux.dev, io-uring@vger.kernel.org, 
	Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>, 
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com, kvm@vger.kernel.org, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, linux-arm-kernel@axis.com, 
	linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org, 
	linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org, 
	linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, 
	Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>, 
	Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>, 
	netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>, 
	Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>, 
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, 
	x86@kernel.org, Zi Yan <ziy@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b="S/9ips/0";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org;
       dara=pass header.i=@googlegroups.com
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

Oh, an your reply was an invalid email and ended up in my spam-box:

  From: David Hildenbrand <david@redhat.com>

but you apparently didn't use the redhat mail system, so the DKIM signing fails

       dmarc=fail (p=QUARANTINE sp=QUARANTINE dis=QUARANTINE)
header.from=redhat.com

and it gets marked as spam.

I think you may have gone through smtp.kernel.org, but then you need
to use your kernel.org email address to get the DKIM right.

          Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAADWXX81Y3ny6WvDN8EeYvBPa2qy10PKhWfZpj%3DVBcqczL6npg%40mail.gmail.com.
