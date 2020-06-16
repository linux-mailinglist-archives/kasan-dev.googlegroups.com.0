Return-Path: <kasan-dev+bncBCPILY4NUAFBB2V7UP3QKGQEQN3PNEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5564E1FB588
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 17:06:19 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id v8sf14023947plo.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 08:06:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592319978; cv=pass;
        d=google.com; s=arc-20160816;
        b=S80zvp1HRQtnd2+36Nwn/1+8wgaI0JoI4/MxYUQJMuUJT4ZsU9zJ1idxe3genbzuwR
         YYKisHmTbYF6m34BaJw58wGNBwCJDMwyFOJT2aiaz1ipvuvnMi+sGImj7xuofZn24obI
         QmfzMkd+vBVGJ3cA3M8akHtyzpA47pMTk4/86xGLvWTqWZS74NsGEOyg2SUvUd06RIkK
         y80WwOexnDxP5FukIJgmAp88FoIf3vHa5KPWrB4WwU/hgL12db4EpaYyX+m5kNcU0yd3
         ixfWGySiKBouEB1gpcwcPs6IY9sHJWACZapfUp/ArRlqI9BZWr5/d+cN8WRfCTfmRGqw
         z/Ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=hoa62CVpAPh6lfe2C6WhP2AoOcjL1qZJX1MuNMQ2JzE=;
        b=NrhcEGBdbS8F+x9IZlj3XToYOlX66Wn02GuIob5HqKSMFLeCFlSDK+Is/DU3T9aUFo
         zj6lRAFDUBXmEAw5NVRhA+ixClsctr3Y0ndTjv9+udwEqwLiGSogSNGT7/QW9F2kyAas
         i9tRDrVJHJxmopXeJ6hmo4AG3eF9MZhHsJuFQSGS5lPtgYMJn/o8N+/m+utvYg7bwahe
         ujKl7xxdrnAqE6P2kfIPPnYQsHP4CUILd1p1NZimGWqT8AUJAesqCzbNBdvL9L0VwQ9E
         Dc8qfdM24kKCO91KYHCxoSrlfcXAEVA1Kp080oZ5GoOMhsXSfjBl0EGumoeL32kVT1jd
         RLqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GGqVzPSX;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:organization:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hoa62CVpAPh6lfe2C6WhP2AoOcjL1qZJX1MuNMQ2JzE=;
        b=cKQFyVPbVj/tr11q5uNhH0vVrI7Ox4AO3bROE+C5WV2FSPI8vcoIFCVdSovDMo3QEW
         d8H2mYMIGwWsnwAky7OTF700x3R85CWLl1YNsFhMqFggtaxnCGDB8SXt8WjNfe8azjxa
         KMdDE2IgQa6xVruI5E6KZylYsIh504hVmAio9dZxQDTpGTTAjaWASDFlfkt4bGzjom+A
         lTY9PGc2LblxKx+vl/GTWdoj0HnrAfhDNCvzlfCAQXY7IO7GbZaZGggSsHXF0f/htQY2
         lNu//IuGSrkmFh6wFbo3Umsey9WrTpS/33hVBVTliKb41PMce/6eZqxzHXzRCkC7BmGI
         2eEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hoa62CVpAPh6lfe2C6WhP2AoOcjL1qZJX1MuNMQ2JzE=;
        b=st5QKP0aFLyVRcNmsK+gITarhVmU6AWuviIqk09wdMbgux274aH1kFsZkRFt3b1bSd
         CVuuQhei8VQcDoSBLYOUBqoUDEOLPRQPrSTezrVQTQYO3hgW0sImYYXcz5FNgk2RbVev
         L7zenUuelXW73KESs5xuTKE69v76FCpEJwzBiHgQpbKzQrzs00UyFYNHOr0h4P5EW4YD
         dQxuQLob1PJtg8VJ90FCTDlZa/kbNwK/OUAVSFQGXv43vuVv5BLUu/8xEjtYENs7/+Wc
         pdWBVUopsyQ4GL+Lf+c6I0NcCi1KpGHOm32w8pch0DX0TrzrRw3nrbqtjozdiRzA5g91
         L+gA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530r1T+k8zZB57gTz466Qscc/DEsqVhntVBM67TM0LwhgeRORwo+
	i8qoUGfUL0/esfvOQxrazjM=
X-Google-Smtp-Source: ABdhPJxBy/HSgY/XtE1TFmbILUWZ/WZWWn0PYD7059Dy7wgoTNiYFSbs7SvgSKCcZi0xlJZYeyeAKA==
X-Received: by 2002:a62:884b:: with SMTP id l72mr2575132pfd.242.1592319978065;
        Tue, 16 Jun 2020 08:06:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8f3a:: with SMTP id y26ls5231091pfr.3.gmail; Tue, 16 Jun
 2020 08:06:17 -0700 (PDT)
X-Received: by 2002:aa7:9d9a:: with SMTP id f26mr2417807pfq.229.1592319977623;
        Tue, 16 Jun 2020 08:06:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592319977; cv=none;
        d=google.com; s=arc-20160816;
        b=gTMp9uSxzNeTj/+PHwF7QbbcrfEBd1Rd2CGXgbjV7B2PQ/v7Z6xEJ345RufUFyO3xG
         rifLSevMlTCbkQSHKrF0aB8GX92ru3rBuC1V0/jomr89vczspcST1OlJxbI4QLxGwDaC
         LSiSc3PS4stT/QDTELw8prYQmF/qDcZlPJaG4g+htjC9Gn2mG6HI4Je88Nda2IJQoXIo
         aGIj8LmZ+tYWFN9L6Y7p4QPqoJHCWGQATba8dptyj/aGz9f9qa1UdslcvXREvhLon3w0
         KxEnN7kV+RIJJhoNBatCFKrd/HuCvjQ9oxPDoBDHZjfwNUzYXSxs9l2b2+Ch1/G478ux
         wtqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:content-transfer-encoding:in-reply-to:mime-version
         :user-agent:date:message-id:organization:from:references:cc:to
         :subject:dkim-signature;
        bh=zMJwLzxJj7q5lIXa5apx7u6nKtBFyLcKdF8jh3rUT7U=;
        b=XD2PawC85hLRsFhURv+U3D3sMJR6JcQzGE+1WFxlCRuwaSULIv3G6FjyyzjoMTTsZU
         voDE0nqx3ZSKpzu7gWK6TPh613TIu3F16aD/i/C1VKoW5DCXNllfqm/bEg/Q/TH6ZuVO
         F9ivwCeCzefbRFjZtAeHvPGiVdVdHNzgRyBLbmAy0fhNUYYK4Hs7xghirQy7BxAfhJGZ
         4b+ZRtBHV+gekv8kiYLS/HUOSXfyt08mSbB1FZjmplU2/b8FjaeMN1u075nGQQLCRm1c
         er4IbpdMf1WuxWh2mZt3OSX6xI8xNnc6t3kVyFOesizZ6mFxCqlRIq9ZJbENFZWLcNFG
         zxbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=GGqVzPSX;
       spf=pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [207.211.31.120])
        by gmr-mx.google.com with ESMTPS id x132si887194pgx.4.2020.06.16.08.06.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Jun 2020 08:06:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 207.211.31.120 as permitted sender) client-ip=207.211.31.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-443-zoZVocg1PeKVqdkZgJCjfg-1; Tue, 16 Jun 2020 11:06:11 -0400
X-MC-Unique: zoZVocg1PeKVqdkZgJCjfg-1
Received: from smtp.corp.redhat.com (int-mx06.intmail.prod.int.phx2.redhat.com [10.5.11.16])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id ECA125AED8;
	Tue, 16 Jun 2020 15:06:06 +0000 (UTC)
Received: from llong.remote.csb (ovpn-114-156.rdu2.redhat.com [10.10.114.156])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 41DFF5C1D4;
	Tue, 16 Jun 2020 15:06:00 +0000 (UTC)
Subject: Re: [PATCH v4 2/3] mm, treewide: Rename kzfree() to kfree_sensitive()
To: Dan Carpenter <dan.carpenter@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 David Howells <dhowells@redhat.com>,
 Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>,
 James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, Joe Perches
 <joe@perches.com>, Matthew Wilcox <willy@infradead.org>,
 David Rientjes <rientjes@google.com>, Michal Hocko <mhocko@suse.com>,
 Johannes Weiner <hannes@cmpxchg.org>, David Sterba <dsterba@suse.cz>,
 "Jason A . Donenfeld" <Jason@zx2c4.com>, linux-mm@kvack.org,
 keyrings@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-crypto@vger.kernel.org, linux-pm@vger.kernel.org,
 linux-stm32@st-md-mailman.stormreply.com, linux-amlogic@lists.infradead.org,
 linux-mediatek@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
 virtualization@lists.linux-foundation.org, netdev@vger.kernel.org,
 linux-ppp@vger.kernel.org, wireguard@lists.zx2c4.com,
 linux-wireless@vger.kernel.org, devel@driverdev.osuosl.org,
 linux-scsi@vger.kernel.org, target-devel@vger.kernel.org,
 linux-btrfs@vger.kernel.org, linux-cifs@vger.kernel.org,
 linux-fscrypt@vger.kernel.org, ecryptfs@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-bluetooth@vger.kernel.org,
 linux-wpan@vger.kernel.org, linux-sctp@vger.kernel.org,
 linux-nfs@vger.kernel.org, tipc-discussion@lists.sourceforge.net,
 linux-security-module@vger.kernel.org, linux-integrity@vger.kernel.org
References: <20200616015718.7812-1-longman@redhat.com>
 <20200616015718.7812-3-longman@redhat.com> <20200616142624.GO4282@kadam>
From: Waiman Long <longman@redhat.com>
Organization: Red Hat
Message-ID: <72aa954d-4933-333c-b784-f8df14e407e6@redhat.com>
Date: Tue, 16 Jun 2020 11:05:59 -0400
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.4.1
MIME-Version: 1.0
In-Reply-To: <20200616142624.GO4282@kadam>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.16
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=GGqVzPSX;
       spf=pass (google.com: domain of longman@redhat.com designates
 207.211.31.120 as permitted sender) smtp.mailfrom=longman@redhat.com;
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

On 6/16/20 10:26 AM, Dan Carpenter wrote:
> Last time you sent this we couldn't decide which tree it should go
> through.  Either the crypto tree or through Andrew seems like the right
> thing to me.
>
> Also the other issue is that it risks breaking things if people add
> new kzfree() instances while we are doing the transition.  Could you
> just add a "#define kzfree kfree_sensitive" so that things continue to
> compile and we can remove it in the next kernel release?
>
> regards,
> dan carpenter
>
Yes, that make sure sense. Will send out v5 later today.

Cheers,
Longman

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/72aa954d-4933-333c-b784-f8df14e407e6%40redhat.com.
