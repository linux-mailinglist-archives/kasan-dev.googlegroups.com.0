Return-Path: <kasan-dev+bncBAABB7XKYHFQMGQEL2IUSMA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id EEvCMn91cGktYAAAu9opvQ
	(envelope-from <kasan-dev+bncBAABB7XKYHFQMGQEL2IUSMA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 07:43:11 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BB4D523B7
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 07:43:11 +0100 (CET)
Received: by mail-ej1-x63b.google.com with SMTP id a640c23a62f3a-b8735332877sf773693866b.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 22:43:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768977791; cv=pass;
        d=google.com; s=arc-20240605;
        b=iyqw2MA2/TbsmKQrwTeygKDF5pUuVifQRoZSqMZrHmpF4HjCeBP2ynQudijRDvm/oF
         Mlfi0239mHnKE92+yfilnROjofMCdzIg2TTuoyl6HWnXPkHcBG6EM3p+yOe8N7GDa95j
         ImJ0sQp9yokoaIKNTGHhWXoiqUbsivMqqRRSjaeFZxUKKN3p+ondgcOjgu+vDTWJOBv7
         vmxvC5hDtPOw0AHiAh0ipPFZjmM+plg323sgl8IyR4kMA/+Sk6f9bfrzujnu4b7pJoVR
         tcU4erfVQvi81mW4uR2X5EYx7rt5YbIpSGkjTaC1V3CLv4tZnrLNtDnE/GadHWeX9g2M
         7dbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=q33JKqS2wnYTNv18pAdKkcbafq7/222Mny01IxzrG0I=;
        fh=uI6TkjY6qIqGphmSptnmoItNVsFZ8BrgGff0ysm858k=;
        b=cMwe7ZPKH9zSiENMl8snVJq8IiOF7TCPYIoored3/6ESuBwdMI0VggVfucKeCpoWAx
         RU+Xdm2BiiLeSzajSHH1Nmxm4T9bL6YBMfhn0WWHIIJWR7ij+n7nTlAoFyqm77AA4ws+
         Pfbsdmofm5DlqvF2a8NmBrM87vVh1p8HJ7NaoyHF84iaN4zXN7pIQkq2aE0R95S83aOp
         CgtBfhDgwKny2r1YcEMflYE8f7S8EOm76poSYlwNo1AePJgVIOFDwOsNat4UCym6NqAM
         VuXxunY5/uWLNTiRTNNpIJkXeRruTL2ucRPNMD1vOUwEzvUX270TWmN2/98CzSmTMFGf
         q+PQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=PmisL8fV;
       spf=pass (google.com: domain of hao.li@linux.dev designates 95.215.58.176 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768977791; x=1769582591; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=q33JKqS2wnYTNv18pAdKkcbafq7/222Mny01IxzrG0I=;
        b=RjO+rnzDNdsPZ48m3UwpxJJWGW6+4dOpafiJ/jQa7ESC0vibq2Me0R/Jd6tYS0yDgC
         0TXpcag33c+QG2/HfeWleVIJTIJz6tFtWHNWrdtjz4IDztZy+qqA53bGjvaUzQXG4XAZ
         4+5w887QVMvs1Kgcupozh85F/NaBWrnH/lzXC8KhJfSzFX5C0/Rh+Qj1CCLqbx2laUtH
         q9KNdrLYMbWXV4Bh1czLfkoYBPN/j5VfmixIvR5nN58bHWC/f/2vd74snJYFylfThMSy
         Qe40VPOXge25ZqGl1A/+tDIyxR4EFpbuNbidBJ1Jz+ZQ8xOFbO25OOIxiIll7eX3TA5Y
         vtoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768977791; x=1769582591;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=q33JKqS2wnYTNv18pAdKkcbafq7/222Mny01IxzrG0I=;
        b=gQ0VifIpUBtE0As098lzF1IRTo4PkGY/hGNgv1xbqZcHj/7Cz+4s8s80qlmpHOorQl
         5AdSDNT+mlwK1dRoRezJ4r2EYIfOzys1quDL4V9AV3U+W1G1/Ses3/RydbgWUq7KhZuK
         lAEcfbah27oNddUIcsqLeFb4GyTHkHO/A+vObcKZFV6em6i14KcnaKNJoAdQ7O7AcNiV
         4k9yB8tATzPvY4Yp12bPReYHP/SvLVZ614xfUqOiKUa0ZYUWeQpojOmdaSo+XOu/Vah4
         wCnmj0sGpOhIKbWkIWC0H9EAUpsQbb95Dmy7QJaI34j4GjxIMHS69nb5TQEpSxymJEbS
         ZrnQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWXdEuwJbrsvv+AtpUM+/UO4CM1o5VLEF0buNCzFOh5J8yoZlNxAx8LqCILo4oEHeplwUSJlg==@lfdr.de
X-Gm-Message-State: AOJu0YxgFsLw4NiJqVRiRhYMDXwnCRDCK6SvFdZU9zGs/p0dqZfV2S12
	tckGhyeYnx6RGl19hwFlN0s7S7g08dLdWKeyS2xQZ3ybk6p9wxwNULjy
X-Received: by 2002:a17:907:2d9e:b0:b87:908:9aca with SMTP id a640c23a62f3a-b87968a9870mr1388457966b.9.1768977790674;
        Tue, 20 Jan 2026 22:43:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F+/c3vhh8j8oaQyFmx1s1jW2fw91ZY2NwYUU6k0iRLKw=="
Received: by 2002:a50:9e82:0:b0:64b:aa45:7bf6 with SMTP id 4fb4d7f45d1cf-6541be912c6ls5156220a12.0.-pod-prod-06-eu;
 Tue, 20 Jan 2026 22:43:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXEpGLrc5GHa2a/ZjzrCg0xnO+xkkt0kl+Ty5z9l5itVNXu7IYHnFId2dIEVXN0FsGDmtujtuEjQF8=@googlegroups.com
X-Received: by 2002:a17:907:944c:b0:b87:324b:9ae1 with SMTP id a640c23a62f3a-b8796aee9ccmr1570610066b.40.1768977788871;
        Tue, 20 Jan 2026 22:43:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768977788; cv=none;
        d=google.com; s=arc-20240605;
        b=gMMknte61bHkfedAZriMQ1NoR+xXXMTXuzjfZTZep2CIo9mqwDQ9jf+DAcSiVWCWzb
         wuR2F2u6JiEj0EyHqrsHxArKyOg/ZvOjNBsapEuSZA4dAI3NNbav6xd1zQEStVQf7qsd
         cpH/rA0W69/jCTiJKMEmsv1OUHL8uG8w9cyC8jlM2t5y4badpCDK1IKnCRM+AoPPUoY2
         aqQroUcsWJamgIW6RWWegnEN2hgbZhkaDItQi9mU+j26taOEOWeFQEgy7zpAXePBEQ2K
         fRk5y9g+7jlsiBqD3tZrUJeVBimQaM4LL/XjOeZys/RFP7v1OFfEusz5yzixnpBu2FuP
         bpjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=hGJUEukW1YF975sFGms4Vf9mUEAliFTKB8iTKnSd2tA=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=TjnhooCLDQzQsrm0zH4aoLZWH8INhYJ25k5x3/iJ2/lHngIhoio99y+8dPyWes2Ag4
         nm2S2tkXhGpS6KbUBGtItcM2jeP0X0H4LhMXoOBRe8CcCMXghtmlvyPfnjkDB18kuIfa
         mTbQT0gj0I9vXJipw66uLlG9/we/qwrFRQr/Ko6GkC61e8m6YdhkeYRCJz5pJoGFarvV
         7JeRkxGqBLidYqwJohYhw+jAh/NNES4OKyJWnQQM2Kil74HRMP3Zc2aVGPEXJnXL+p6l
         ZTLam6SsVsgWhogh/8sZoCKLcGlx+kljhEft2sDWJEf0IzwlIhvGa4zHDcuUjNBdvHOm
         88iA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=PmisL8fV;
       spf=pass (google.com: domain of hao.li@linux.dev designates 95.215.58.176 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-176.mta1.migadu.com (out-176.mta1.migadu.com. [95.215.58.176])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-65452cca91fsi235339a12.2.2026.01.20.22.43.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 22:43:08 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 95.215.58.176 as permitted sender) client-ip=95.215.58.176;
Date: Wed, 21 Jan 2026 14:42:49 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 16/21] slab: remove unused PREEMPT_RT specific macros
Message-ID: <v6govsosryla4nzgzbfo3eeiziabn2tdprzhg3zcpoxkxq622f@2ra34j7326mn>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-16-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-16-5595cb000772@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=PmisL8fV;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 95.215.58.176 as permitted
 sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=linux.dev
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
X-Spamd-Result: default: False [-1.11 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_NOT_FQDN(0.50)[];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[linux.dev : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_COUNT_THREE(0.00)[3];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	RCVD_TLS_LAST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_NEQ_ENVFROM(0.00)[hao.li@linux.dev,kasan-dev@googlegroups.com];
	TAGGED_FROM(0.00)[bncBAABB7XKYHFQMGQEL2IUSMA];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux.dev:email,mail-ej1-x63b.google.com:rdns,mail-ej1-x63b.google.com:helo,suse.cz:email]
X-Rspamd-Queue-Id: 6BB4D523B7
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Fri, Jan 16, 2026 at 03:40:36PM +0100, Vlastimil Babka wrote:
> The macros slub_get_cpu_ptr()/slub_put_cpu_ptr() are now unused, remove
> them. USE_LOCKLESS_FAST_PATH() has lost its true meaning with the code
> being removed. The only remaining usage is in fact testing whether we
> can assert irqs disabled, because spin_lock_irqsave() only does that on
> !RT. Test for CONFIG_PREEMPT_RT instead.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 24 +-----------------------
>  1 file changed, 1 insertion(+), 23 deletions(-)
> 

Looks good to me.
Reviewed-by: Hao Li <hao.li@linux.dev>

-- 
Thanks,
Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/v6govsosryla4nzgzbfo3eeiziabn2tdprzhg3zcpoxkxq622f%402ra34j7326mn.
