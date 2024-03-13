Return-Path: <kasan-dev+bncBDXYDPH3S4OBBEHCY2XQMGQEV5R7NDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id DAE6887A8D8
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 14:58:41 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-33e70016b4dsf3662511f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 06:58:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710338321; cv=pass;
        d=google.com; s=arc-20160816;
        b=gtsOkqG1+7l9CsDO4PQOTFLLuhY73h1Qe71Wi99rqLnMEGb3G+CoAvZC0m5BPvbx27
         x/ee/FoVmfWgg9xYl81sa0k4cUc++AXT2rcUkTHI2CxEQEnELUOW6jOpUNLSH+5YrAbA
         b1i6Z7RfUkQdMoMWf5IoPS0O9obaT4Fk2PBtrT/Hl5t5FfUE5kXZO4wCZs4VIjHdwTaw
         tVFbUAGNEmqi7uMdJGroWGxd/MCWZTVcGunoWZT/0MgmB7dqrj6gkcjYhOXXN+0ip8I4
         O1bqnX7v60YESpdP4hwpE4/GKQiNn20Nz+SuisgrzO/4welYxICgravL004E9AAHb8AG
         lwHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=ZAZkxjdpa8I8fB/4tM9J8f42GBGQA+K35hxlWcONxvU=;
        fh=3gtRGnjdxisXBI81szHOLP0N0ULPtd9F5RFhZDK+U6g=;
        b=zoBhomzBGDPHBOruJJO+/yn5tKcRH+lMGnL5Szn8FJJfmmIa0DOMe3AOnuaBSOVdcz
         FyvwBra47pCi2syFefCDvAWjq4KCyHy/VnDsTt8wyEBsV14XBPkL2WOAHp5CEF7yrAD6
         9k0Z+FunCwomHupp5j31up2PAccWHBRVCcOvIvh4thX42IU+cLSFB7nGcK98exSd/3kv
         2eRvJNTdQ4JzcygLWcevFrU9KcBEeEbElThj6hJHY7Do9AfOswKmLA7m45bvhvgwXtLX
         hkDdqHU77rM67BQbhYNR5MiNkhNwU8BcdZpa9rhPHnZmo6+31tZUrErnPYbn8cnf6s9J
         HIhg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=EXHDhthA;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KRdmYukr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710338321; x=1710943121; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZAZkxjdpa8I8fB/4tM9J8f42GBGQA+K35hxlWcONxvU=;
        b=AXPr/IMC8D2yhEv6goXtqxkt/QyskhCcII13VQyYeF1TyNjlRkWApXeo7pGrGALFDx
         9KX5jCV6+HviNSYXOOtI/b0RFuFxDdBfDDTKbYlasOdhrzlmLET3U0EGvSWIvZzj2g1u
         57Ot4d2P3AbtcqLf7Ej16NuYKxOp2lhYke5bdek4R7Z6UVvlQquCIGenwBGjSy5eJkBW
         a+vyowMUgEkLDXNwc2F+txnQSY5yGWeNy5JpuwjfI5Aa0a9ZjCoRWMV9/1WOB5o5ssZ+
         21SlLEeiqAUE77Kr0a7FURq5Dy6FSay1T42RrFvhZQo5g+5VflYgBqxtniLroH8OHggB
         4bMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710338321; x=1710943121;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ZAZkxjdpa8I8fB/4tM9J8f42GBGQA+K35hxlWcONxvU=;
        b=eRgFAiwwCl9dC6BQUFx12Q0pz2opudLnPXbaZ/HmUnre04NDEK6Vc7bK0e9ZQFniw4
         Iv1C+SARmOp0NAGnLCm4MIzHD3YtGiD4ToTGvg5/wja+hl7ran1VXaTw2O2wR/LYu2cD
         m60aKFVK7qguXg+qo1+4p3X0PfjxxD5ZFmsAltHla+xalugkZxqXXAaQRZ0hFc7LogMt
         N3NZRAN0YzXTr1GXuXrDCKnq1g3DJGbn2IRDIKducqW/98MS6OYv1CG8VGrsfQgWUY40
         dohb97Wqeiyr9XVuaxMxQcap7sNF9fAXjX385gFFUTHiunf3MCIvahZ73ePvIxHF3e/e
         bDCQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUNJoy5U3xlLGHyzl2BxmFioz51rkbLmhY2JqPWgf/aZ7SULe0Ht4nsO+2beK0YMa3mJ8xLiHSpfKEEwdYtd4qKWCMpIUOs4w==
X-Gm-Message-State: AOJu0YyHzD6TpZA3/F5zcTvcS9NlAnboAHHUmcMNpgUohVRB8LyJ5otY
	YAGp9EwDv5XIsqMxK7ksvNEAD0AnW/tiiDHLoGf9WoP9YbifcqJs
X-Google-Smtp-Source: AGHT+IFdTDoYKk51uCRHMaNtsR3NN0NgDNGQeDNSxFFsz5Y6HKval9XxSRl5EEt1xjwKvQnV1JxchQ==
X-Received: by 2002:a5d:4802:0:b0:33e:6366:5f2a with SMTP id l2-20020a5d4802000000b0033e63665f2amr1850566wrq.5.1710338320884;
        Wed, 13 Mar 2024 06:58:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:58d6:0:b0:33e:c0d3:ebb7 with SMTP id o22-20020a5d58d6000000b0033ec0d3ebb7ls2687wrf.1.-pod-prod-08-eu;
 Wed, 13 Mar 2024 06:58:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVy+ZvD5iHMMl7ymkuzB1eP5In+3xbCDo4OGriWmUY5nCgCCv69b/hXlqqQord4nHGmTlRMNKpxrN//a/4EG1EFczIm93xK55Us7w==
X-Received: by 2002:a5d:6d03:0:b0:33e:bfb8:7320 with SMTP id e3-20020a5d6d03000000b0033ebfb87320mr340750wrq.7.1710338318922;
        Wed, 13 Mar 2024 06:58:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710338318; cv=none;
        d=google.com; s=arc-20160816;
        b=ELUAymxTpc/aEwacmk+lYgRyrT/n7p/xFMlddp5Yf9pFpO09tJMLvxDJ66egJIqU3P
         FYIGyp2gcAwyrBMO/8Kmf7Si1767EEHu5UpQgPxulDpfk3TmEbJPm4Tiuwi+P6N6O4tf
         eYH+zuNzFSABMaXTQZFPWplwGwRg2DSOkx0jWcW/SmaUbDRnJIgGnAsR4aiMNTbUNsHf
         c9hLChJPSQhh3drCltJuKlX3Zfbee+Zx39bPKWYym41pRJMVv6eri/9w7MKbWCA2Lf5v
         LwXl4oO66ixvKxp21cl7kpfupistDGXlKv70I3HEfW9j8fQO9BC4lb9+/bnDpuefAmWz
         9pJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=TpodtcSm7Y+i7tvMHn/lmmFNHmbivL/zCj7us76Dghg=;
        fh=Q5QK3mEHpiSw50+k3en+vN00KR+pxr1dxz1JLzJfHmQ=;
        b=UoVNxOxsrai2IA4UVhy429YAsP3reoi2oiYrBVdvcJAyIpE4x/yd5H7z2WcTw5Q3/N
         gvj7t+ikXJXvuK0L5n41DIft5P0nRsA7XjaceWiTQjqhngmsaCy0KDKl9nJrnNFw6MrA
         Zry8MmWuYIrxzEeB0F1g7ikS7+oOFvnX6gPytq9UCHRgRnJ3M4jW+Srk6u3M81tQsqc4
         2lwhfCJpgB1JlqaXg3fC540XnNYeWMk8tvamGlv/CZ+l/MQvNw6/zdAqD7qJaV4/c9w8
         VKnk4rK2qcb0Qq3JGuyrNUCsIrFuu52I6gkuke87G3AH4SCw5aX3PLwqflK6lIA8ypSb
         4JNQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=EXHDhthA;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=KRdmYukr;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id fx12-20020a0560002d0c00b0033e7e5930b9si532805wrb.8.2024.03.13.06.58.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Mar 2024 06:58:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 5716721C90;
	Wed, 13 Mar 2024 13:58:36 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id A23021397F;
	Wed, 13 Mar 2024 13:58:35 +0000 (UTC)
Received: from dovecot-director2.suse.de ([10.150.64.162])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id aqbWJgux8WUXVwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 13 Mar 2024 13:58:35 +0000
Message-ID: <6dbd1faa-16ec-4058-b01c-98f25053303e@suse.cz>
Date: Wed, 13 Mar 2024 14:59:16 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 06/37] mm: introduce slabobj_ext to support slab object
 extensions
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org,
 muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
 pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
 dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
 keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com,
 gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
 vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org,
 bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
 penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
 glider@google.com, elver@google.com, dvyukov@google.com,
 shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
 aliceryhl@google.com, rientjes@google.com, minchan@google.com,
 kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <20240306182440.2003814-1-surenb@google.com>
 <20240306182440.2003814-7-surenb@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240306182440.2003814-7-surenb@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-1.75 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 TO_DN_SOME(0.00)[];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 RCPT_COUNT_GT_50(0.00)[76];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-2.95)[99.77%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DNSWL_BLOCKED(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_MATCH_ENVRCPT_SOME(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:dkim,soleen.com:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux.dev,suse.com,cmpxchg.org,suse.de,stgolabs.net,infradead.org,oracle.com,i-love.sakura.ne.jp,lwn.net,manifault.com,redhat.com,arm.com,kernel.org,arndb.de,linutronix.de,linux.intel.com,kernel.dk,nvidia.com,soleen.com,google.com,gmail.com,chromium.org,linuxfoundation.org,linaro.org,goodmis.org,linux.com,lge.com,bytedance.com,akamai.com,android.com,vger.kernel.org,lists.linux.dev,kvack.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[];
	 RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from]
X-Spam-Score: -1.75
X-Rspamd-Queue-Id: 5716721C90
X-Spam-Flag: NO
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=EXHDhthA;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=KRdmYukr;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 3/6/24 19:24, Suren Baghdasaryan wrote:
> Currently slab pages can store only vectors of obj_cgroup pointers in
> page->memcg_data. Introduce slabobj_ext structure to allow more data
> to be stored for each slab object. Wrap obj_cgroup into slabobj_ext
> to support current functionality while allowing to extend slabobj_ext
> in the future.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6dbd1faa-16ec-4058-b01c-98f25053303e%40suse.cz.
