Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBZUHXCNQMGQE2YLU32Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 333BD625502
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Nov 2022 09:12:23 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id i14-20020adfa50e000000b0023652707418sf801812wrb.20
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Nov 2022 00:12:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668154342; cv=pass;
        d=google.com; s=arc-20160816;
        b=dWltzf5HLwJGCEFOawQmX3rqAo3A0IFMyRufyW7QfKyPSl2MLO2XUAjaaTWoBZkOrE
         /Cjk5cac7iVmLp2/hwLsJDkb1d2GLxLaQOdj6n/awvcxXUg62zelD6HhBHgQN9/t0yEO
         2hoE82WScNwIX7XOEMSErVL/5IB9idp/Do76QvHPOlxfQymKZrux4ShxX5+gMrB+AWMQ
         NAj507WLrY+FT2a3FgQrIAg8OojesLi0yRNEbPXXeOR9qTdSW2W5dXvta/s9wytrqMk3
         Nh7E6Ox3NdHcup0pD93ebqE3acLV8TDvDFnV1T+/eBQXs1jUNNdtbs5r9VYINrxVvzxR
         hsww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=JazwTezB3j+s+Yvqrn0LZRsb7DhP3Od2s3QRwzVZSK0=;
        b=Ll+BxKpiNzgsVOttKHPcof4tlcOaLZqNMQk1eqlm4fkcTHez4bAUUh3VxZ5aPxM1Aq
         aJ4zuiTOIOgvsgHEGnuvjEWcKYyF7+rINGBZS6av2pEEja7qkAfZAz9vv0P2HGX6TQ9T
         xFLCioipYAZor0DioTsPgNRcP/5k+D25uNufoH6wfZgWdcmaXvrPhnOfyzU2bpmvojrs
         4CPk+0b1B/RSD0j0vO4THOV6BYPRI4D+BQreeilJaoIRr4nNYqFovhJzlqYw9VmpCrNT
         lK3Drzu372s4DPTSPQcac1dCzDWrZ6sV9MK0It1VNJZP1Fs/DImRklUVzGKw4SzFe1GV
         76mA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=G2Mdh1hQ;
       dkim=neutral (no key) header.i=@suse.cz header.b=WIuaxZ8t;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JazwTezB3j+s+Yvqrn0LZRsb7DhP3Od2s3QRwzVZSK0=;
        b=XIE0lt2tuWTWiFTox9Ou+yUwnRLtdAoaAZhgV+5DckHoApfHiPWRIwv3pc2Z/qOSfw
         IvfdummMyIXAYVmFdZOwO01TILBLqjnyg7jfubEMtDRCGIge26XlwYyUS3D2qE932Nz/
         YQ+5WUHdhiFHkuaqSx9WPVD0ezhiEEtOl0HeFS1nJbi6Ae/NYLcK3KRLfs2WptsT5op7
         aekK+qfbl06c/C6bwwF33V+/LnfiCOM5j0FoKymw5HyWa6jNxLf2R1U/ZCsKMKvO+3MC
         ow/kRn9BIvu3ADJsV3fzDiKUPmaqT9JlEr76UpsIT2vELN3DbapLBtF9XFoWMS9JcENO
         AVtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JazwTezB3j+s+Yvqrn0LZRsb7DhP3Od2s3QRwzVZSK0=;
        b=LYJA2NIwlarbBeK7Bb78Xb5cqAV1UvRZ0/M6fb6T/0PHiFkvMdoDOBXv1x8SXVO5St
         4hX6Stz5dHxz/unAvAAt32+E/1+XcFBgOKeXDiJDCGmVLMMQ2n+aXarVlYpvdVcgf6v1
         72Gqut5U7LtLtotvzCR23vaFEKAnIAbMToIOfmKx8TfD4pa+CcNmKSekV+yMG8wPOPt0
         TOe5G7IJzxVG95am8Fh0vDZoOPJ3BjkBLLajJW+iKnhRwXQ3VeLovFhQTH8dCIVaNb5y
         KaM8S7boHnb0ZkoztzXNVP+it2McE5S0+yRv4HVTRcosOKPCvPOQLOGMqIiKooJ8yHMz
         SIFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plzP7G8aCo5f4VJME1NFtycCA3PdrFfDHO4dpxa5g1HlbrM+GfR
	BInQBnrBQFfmV/oMj47q4Rc=
X-Google-Smtp-Source: AA0mqf6CpziyU4UsuGWsRWOYO3kCENH+PBVrRrt37v4lchZM4uKqAhpQfPn1aiAUys2vv5UmQ4YPYQ==
X-Received: by 2002:adf:f446:0:b0:236:7439:61e7 with SMTP id f6-20020adff446000000b00236743961e7mr511882wrp.611.1668154342545;
        Fri, 11 Nov 2022 00:12:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:602a:b0:3cf:9be3:73dd with SMTP id
 az42-20020a05600c602a00b003cf9be373ddls3680114wmb.3.-pod-canary-gmail; Fri,
 11 Nov 2022 00:12:21 -0800 (PST)
X-Received: by 2002:a05:600c:304a:b0:3cf:9a16:456d with SMTP id n10-20020a05600c304a00b003cf9a16456dmr419394wmh.100.1668154341320;
        Fri, 11 Nov 2022 00:12:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668154341; cv=none;
        d=google.com; s=arc-20160816;
        b=a280/dk2FYT+5/gblcoTG8xWGZmyTlWfJ4yU2I4tWGGI3L+iHi/I+LHQPMAfTdaK6/
         kij57noWPasAEcKu7HcGd+n+5HHmoGejiOlD2Ah5d0+YwjfMWlTvxy8FEmVDbFDei6bt
         Lqi33b7pgzmszeFqP71V8IiHIMHvKrKR84eE6y00gje/KOodfQ3pzg+E8B4+KrEQXtBM
         hWJQS56s40MSxVtx94e0IE7flA9zfix4EpZYv3QnwHLuMLaREP0yaFMi2qxm/hMSjpr4
         GJmn0S75FdITyVMOiQVAm6bPGhl+9XS5bZhQdt60WzopQ1OkVzcbBjoAt1zweAaCO4ii
         VaRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=rKsv2kApUh0znibD5DPAFWgQv7vvm/xaww+iNqXUWGU=;
        b=ECadK28uVytjffkV1nXm3YlpvwawBHEomkDDf2EHyGfQ5SucAQlbCjWVcaIOzmSl7o
         wexfXkNX4FnXFXMLrEaImxzPXxyLpdy/oa2RCnlsp5yW1TYq2Yv4gbgRe0g8MwfNmcST
         gUyfSxohIvwIoWze+vMX9NOrQd6snYJmNjc80rOUEi6BZGaXLmSLrKLXLWnftwqYb0Fj
         TxA1BrMQvpANGW9wXoueBo1dhKVU4mEfAZdZtAg3gHt/9+U/eEwpnZ7YthBiBhOxp2Yk
         nLkbSje6DQxrzWOzT5sGJ5t64rsgbbPFSXMEenpQYhQVy4VUXHmue25gMH9T/koh8YgA
         bJ4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=G2Mdh1hQ;
       dkim=neutral (no key) header.i=@suse.cz header.b=WIuaxZ8t;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id e13-20020a05600c4e4d00b003c9a5e8adc5si243041wmq.1.2022.11.11.00.12.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Nov 2022 00:12:21 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id DD62E22987;
	Fri, 11 Nov 2022 08:12:20 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 3698E13357;
	Fri, 11 Nov 2022 08:12:20 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id LnadDOQDbmNcNwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Fri, 11 Nov 2022 08:12:20 +0000
Message-ID: <59a0b85a-9001-8c7d-8b98-fd8a87e636fa@suse.cz>
Date: Fri, 11 Nov 2022 09:12:19 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.1
Subject: Re: [PATCH v7 3/3] mm/slub: extend redzone check to extra allocated
 kmalloc space than requested
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Kees Cook <keescook@chromium.org>,
 Dave Hansen <dave.hansen@intel.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20221021032405.1825078-1-feng.tang@intel.com>
 <20221021032405.1825078-4-feng.tang@intel.com>
 <e2dd7c7c-b0b7-344a-de37-4624f5339bce@suse.cz> <Y23vtK4tuBogff+m@feng-clx>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <Y23vtK4tuBogff+m@feng-clx>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=G2Mdh1hQ;       dkim=neutral
 (no key) header.i=@suse.cz header.b=WIuaxZ8t;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/11/22 07:46, Feng Tang wrote:
> On Thu, Nov 10, 2022 at 04:48:35PM +0100, Vlastimil Babka wrote:
>> On 10/21/22 05:24, Feng Tang wrote:
>> > kmalloc will round up the request size to a fixed size (mostly power
>> > of 2), so there could be a extra space than what is requested, whose
>> > size is the actual buffer size minus original request size.
>> > 
>> > To better detect out of bound access or abuse of this space, add
>> > redzone sanity check for it.
>> > 
>> > In current kernel, some kmalloc user already knows the existence of
>> > the space and utilizes it after calling 'ksize()' to know the real
>> > size of the allocated buffer. So we skip the sanity check for objects
>> > which have been called with ksize(), as treating them as legitimate
>> > users.
>> 
>> Hm so once Kees's effort is finished and all ksize() users behave correctly,
>> we can drop all that skip_orig_size_check() code, right?
> 
> Yes, will update the commit log.
> 
>> > In some cases, the free pointer could be saved inside the latter
>> > part of object data area, which may overlap the redzone part(for
>> > small sizes of kmalloc objects). As suggested by Hyeonggon Yoo,
>> > force the free pointer to be in meta data area when kmalloc redzone
>> > debug is enabled, to make all kmalloc objects covered by redzone
>> > check.
>> > 
>> > Suggested-by: Vlastimil Babka <vbabka@suse.cz>
>> > Signed-off-by: Feng Tang <feng.tang@intel.com>
>> > Acked-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
>> 
>> Looks fine, but a suggestion below:
>> 
> [...]
>> > @@ -966,13 +982,27 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct slab *slab,
>> >  static void init_object(struct kmem_cache *s, void *object, u8 val)
>> >  {
>> >  	u8 *p = kasan_reset_tag(object);
>> > +	unsigned int orig_size = s->object_size;
>> >  
>> > -	if (s->flags & SLAB_RED_ZONE)
>> > +	if (s->flags & SLAB_RED_ZONE) {
>> >  		memset(p - s->red_left_pad, val, s->red_left_pad);
>> >  
>> > +		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
>> > +			orig_size = get_orig_size(s, object);
>> > +
>> > +			/*
>> > +			 * Redzone the extra allocated space by kmalloc
>> > +			 * than requested.
>> > +			 */
>> > +			if (orig_size < s->object_size)
>> > +				memset(p + orig_size, val,
>> > +				       s->object_size - orig_size);
>> 
>> Wondering if we can remove this if - memset and instead below:
>> 
>> > +		}
>> > +	}
>> > +
>> >  	if (s->flags & __OBJECT_POISON) {
>> > -		memset(p, POISON_FREE, s->object_size - 1);
>> > -		p[s->object_size - 1] = POISON_END;
>> > +		memset(p, POISON_FREE, orig_size - 1);
>> > +		p[orig_size - 1] = POISON_END;
>> >  	}
>> >  
>> >  	if (s->flags & SLAB_RED_ZONE)
>> 
>> This continues by:
>>     memset(p + s->object_size, val, s->inuse - s->object_size);
>> Instead we could do this, no?
>>     memset(p + orig_size, val, s->inuse - orig_size);
> 
> Yep, the code is much simpler and cleaner! thanks
>  
> I also change the name from 'orig_size' to 'poison_size', as below:
> 
> Thanks,
> Feng

Thanks! Now merged all to slab/for-6.2/kmalloc_redzone and for-next

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/59a0b85a-9001-8c7d-8b98-fd8a87e636fa%40suse.cz.
