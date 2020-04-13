Return-Path: <kasan-dev+bncBCPILY4NUAFBBLN62P2AKGQEMHWIUHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2195A1A6E9F
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 23:52:47 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id b8sf11078186pjp.9
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 14:52:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586814765; cv=pass;
        d=google.com; s=arc-20160816;
        b=imdjiSSvYLNqdpUNvCkYK2txuNEXw0VGrvCZ1D+BIow8PZ8xvnI5CMZAykfzchyMU/
         cbXZML3jBgmSkC9cy0CRDOY/TEd8QwvhaxG6twlcDN/qJDEISAzK8pgbLqZ4mrV7om5c
         RfFESTEorjZc8ogAgCH6LT9aGkMMe5CNAClSolKKyApF+DHSacfUbxEhK1wQ29aYZtWv
         gL+hDUxS/jJVeFESwedtop7Nxd3GzEFsUiJXaoVFwNJJ7vQCX2B46F3Wcdr1KrenXAOC
         ZxsZV7EYUkGbblg1PKnKALuzZOCoHTej7CE6ZGHVLL5u3jtQNdpGYWKuNt0UlacdL06C
         zi4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=8gjJE2+2sVbAAIZiMAtmXSZbI64jjlB5EHokjZUQfug=;
        b=1EdyJyc6VQYoxA2ExhJFY3qlL6U5C4yao+SHvNlXSavLMi7OB98jtzKpHYi4lo+i8F
         +e4TqcI6QPFDxnaHQTPgMRlPAWp78BCu75Ay16Y2VgI4pCYuEApnYVC9UqpHbRrQS4mO
         NrW+mhsWQ+WCUaVV+DXB5IMzsC9T+LeYdygtHCafXXmnkAY9Qo3I55197wGEcEIavCW7
         VhNOpjggfPptfarnOwjPs9Fgh6QDlgS627+tXJaWkm9g2n9aq/HDi2qHMxEx07Ei39n4
         pxW3bRLgqY2u1MpopI/oPwwsr1RqE2pHoYITaMHrFCo4Ccj5DWanqq7JmVKJE+Lv07If
         8rUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=YiSTF1it;
       spf=pass (google.com: domain of longman@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8gjJE2+2sVbAAIZiMAtmXSZbI64jjlB5EHokjZUQfug=;
        b=p4jNwOfduU1YgRQ26ky4aAdbcgqTFq1CRB1Fks8FYN026HAaxRNhaUyqf7UG5Utuon
         jBKt4jbt6spIEB3oYq6TIbqma39g6mbIp7bTJfemoChTKieKkjdM82hx2RkrBaM5WyM3
         4+9OucJR57PEcLsdHADVxGO7fAEbjv6EoJN1MsG1jfRzBnJtd+Ya89T7PYp3T6AzyclC
         Fg3yPWGq+ZWsvBkCi8tzf+hPMTrUaoNt5GtbENT/tWlTSyXr3kgvH6cDwCtp15B5qcCT
         4DUQvHLzacJYMDRys7GYTe3Iki8dOkT8cZfIAdxq0oHEPct9eolx0gRerBIwrdMO/5x0
         d1ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8gjJE2+2sVbAAIZiMAtmXSZbI64jjlB5EHokjZUQfug=;
        b=gll20Ri/6Pi7NWt5hmUgWHI1ZfQzAWpFxM/UadZpqacvoknAJx1zDMxiX6F8P+oKQm
         xLrZS5SiQFi0KPz3nzDTP5PdDHO3d+zKOGO7Z2uRGM47WFEqzRiCqQBJNddXrqVp5+WC
         tF1fMFUHAep1cCG5WgRrqicSetrR7KxRlpQ1qG0NNAYkORYHOde4K6DiYqx1DuWUI4sj
         9reD7Se96SfyHlkYXpuUz5zzmIMQursa/C5Y8PI+IUe9DdUIYz9g1Zldw/mBgTuCxP1g
         k0JoqoSxQtiHki0dWwpg3i/2nrcI+FAffwjWhjY1bse4qbawRXFFHhdBXa8mV3bUkaMp
         mzdQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYvG+OyLirqOp+nKaxJPWELUjvhmZFnbUilVDVNnyhPE95gD7NG
	SDC+2OGmXKE6hwHxL9O6+N0=
X-Google-Smtp-Source: APiQypKEpFClGYIALO7gOW/nY1p7D3sfhJGmGccLs89QurIEcjjP4HX26OPRF0SSgoD+udWTdHOMxQ==
X-Received: by 2002:a17:90b:1b04:: with SMTP id nu4mr23729554pjb.81.1586814765626;
        Mon, 13 Apr 2020 14:52:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ce48:: with SMTP id y69ls1464606pfg.5.gmail; Mon, 13 Apr
 2020 14:52:45 -0700 (PDT)
X-Received: by 2002:a63:7983:: with SMTP id u125mr19757912pgc.442.1586814764996;
        Mon, 13 Apr 2020 14:52:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586814764; cv=none;
        d=google.com; s=arc-20160816;
        b=RqdXHEv3bgoTKzbMDFM/rHJ20VXMHHP695GVYdfPvcktbpXeV4Rhm+nHRa6AJuV9tR
         VdHb+adFDuz7NBoVqKzHAbZEY4nvETYuOvfM7Lpjgogzid9ztwtndBJ96KgMEqXjI1+r
         1pfpJXBlHVwPVhfqZUR6jGZJBXaULE1oLACqDQOtC5OQFSVoxJgOAm4xRemPr9kX8M5U
         rjayUL6sVFfGAOyaM1xxR6h41gOx88jWoNQ6dwBWK2pWSSpq2F6VVqc/C57mIUU3rLI3
         yulbukccmETdzmfByQxImYA9d9oR+WaqrIfmA2zgr+2TA36ws42TN2duZLxGNpfXtchL
         Y8Qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature;
        bh=wxqewLP4iDn0WQn56N4JoZnVO/VnkSCHun6WFS8TA58=;
        b=ghB88VSIKQDRzKViEH79+eG4scgL9MyaOgESps1Ra9QDV2nfiAZqG38U/TIYpKI5Cm
         /VA6iTDQF9LML1utxGGAXYpcTFdUIxenqevrljE739S5gB6j5qCAT6JaDLCD6nXpXIuT
         Pi1fyl9WT57XVc1VikToLtHNojxVBIkcmI0GjfTnM3WxX2ugIZ2wxo2swAbVIXy+b3S9
         n4tOHnoaHHMOTp4LMRJO1jqx/HEekMQJFHUhDGS8DVUTIovtJaAoejJTQ5cDkoCOgNqX
         ndM4MyMmL5O9Usf7omIRlsHCotZONew9z4+dwr22IA0TROc/OiAIjiV7RiDAgJ9WujHA
         anNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=YiSTF1it;
       spf=pass (google.com: domain of longman@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [205.139.110.61])
        by gmr-mx.google.com with ESMTPS id ng2si612239pjb.0.2020.04.13.14.52.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 13 Apr 2020 14:52:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 205.139.110.61 as permitted sender) client-ip=205.139.110.61;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-238-R_QYnAHVPD67nMQL-Amo0w-1; Mon, 13 Apr 2020 17:52:38 -0400
X-MC-Unique: R_QYnAHVPD67nMQL-Amo0w-1
Received: from smtp.corp.redhat.com (int-mx06.intmail.prod.int.phx2.redhat.com [10.5.11.16])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id F1B928018AA;
	Mon, 13 Apr 2020 21:52:32 +0000 (UTC)
Received: from llong.remote.csb (ovpn-115-28.rdu2.redhat.com [10.10.115.28])
	by smtp.corp.redhat.com (Postfix) with ESMTP id AB5E15C1B2;
	Mon, 13 Apr 2020 21:52:24 +0000 (UTC)
Subject: Re: [PATCH 2/2] crypto: Remove unnecessary memzero_explicit()
To: Joe Perches <joe@perches.com>, Andrew Morton <akpm@linux-foundation.org>,
 David Howells <dhowells@redhat.com>,
 Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
 James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>,
 Linus Torvalds <torvalds@linux-foundation.org>,
 Matthew Wilcox <willy@infradead.org>, David Rientjes <rientjes@google.com>
Cc: linux-mm@kvack.org, keyrings@vger.kernel.org,
 linux-kernel@vger.kernel.org, x86@kernel.org, linux-crypto@vger.kernel.org,
 linux-s390@vger.kernel.org, linux-pm@vger.kernel.org,
 linux-stm32@st-md-mailman.stormreply.com,
 linux-arm-kernel@lists.infradead.org, linux-amlogic@lists.infradead.org,
 linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
 virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
 intel-wired-lan@lists.osuosl.org, linux-ppp@vger.kernel.org,
 wireguard@lists.zx2c4.com, linux-wireless@vger.kernel.org,
 devel@driverdev.osuosl.org, linux-scsi@vger.kernel.org,
 target-devel@vger.kernel.org, linux-btrfs@vger.kernel.org,
 linux-cifs@vger.kernel.org, samba-technical@lists.samba.org,
 linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
 linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
 linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
 cocci@systeme.lip6.fr, linux-security-module@vger.kernel.org,
 linux-integrity@vger.kernel.org
References: <20200413211550.8307-1-longman@redhat.com>
 <20200413211550.8307-3-longman@redhat.com>
 <efd6ceb1f182aa7364e9706422768a1c1335aee4.camel@perches.com>
From: Waiman Long <longman@redhat.com>
Organization: Red Hat
Message-ID: <7e13a94b-2e92-850f-33f7-0f42cfcd9009@redhat.com>
Date: Mon, 13 Apr 2020 17:52:24 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.7.2
MIME-Version: 1.0
In-Reply-To: <efd6ceb1f182aa7364e9706422768a1c1335aee4.camel@perches.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.16
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=YiSTF1it;
       spf=pass (google.com: domain of longman@redhat.com designates
 205.139.110.61 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 4/13/20 5:31 PM, Joe Perches wrote:
> On Mon, 2020-04-13 at 17:15 -0400, Waiman Long wrote:
>> Since kfree_sensitive() will do an implicit memzero_explicit(), there
>> is no need to call memzero_explicit() before it. Eliminate those
>> memzero_explicit() and simplify the call sites.
> 2 bits of trivia:
>
>> diff --git a/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c b/drivers/crypto/allwinner/sun8i-ce/sun8i-ce-cipher.c
> []
>> @@ -391,10 +388,7 @@ int sun8i_ce_aes_setkey(struct crypto_skcipher *tfm, const u8 *key,
>>  		dev_dbg(ce->dev, "ERROR: Invalid keylen %u\n", keylen);
>>  		return -EINVAL;
>>  	}
>> -	if (op->key) {
>> -		memzero_explicit(op->key, op->keylen);
>> -		kfree(op->key);
>> -	}
>> +	kfree_sensitive(op->key);
>>  	op->keylen = keylen;
>>  	op->key = kmemdup(key, keylen, GFP_KERNEL | GFP_DMA);
>>  	if (!op->key)
> It might be a defect to set op->keylen before the kmemdup succeeds.
It could be. I can move it down after the op->key check.
>> @@ -416,10 +410,7 @@ int sun8i_ce_des3_setkey(struct crypto_skcipher *tfm, const u8 *key,
>>  	if (err)
>>  		return err;
>>  
>> -	if (op->key) {
>> -		memzero_explicit(op->key, op->keylen);
>> -		kfree(op->key);
>> -	}
>> +	free_sensitive(op->key, op->keylen);
> Why not kfree_sensitive(op->key) ?

Oh, it is a bug. I will send out v2 to fix that.

Thanks for spotting it.

Cheers,
Longman


>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7e13a94b-2e92-850f-33f7-0f42cfcd9009%40redhat.com.
