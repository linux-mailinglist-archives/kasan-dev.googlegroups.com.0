Return-Path: <kasan-dev+bncBCO3JTUR7UBRBDVQ2SWAMGQEGN2OLEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 76FF2822967
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jan 2024 09:17:20 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-40d88fd71f9sf18353765e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jan 2024 00:17:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704269840; cv=pass;
        d=google.com; s=arc-20160816;
        b=oziP+gX4PpDac0hmX6Ptjmu8lwXxmcogImXR/lN7SBkzaIOn7DQK6JMxagHnOgMOMW
         WHQDiTFbXKw02z0fmiqGewAmx6R40cf0e8aVvSmUZpLpIItHTHYyQ+74Zk55Qlh+lEep
         ySUwtD9a8q1ZAu3rmZnDZ9Tlt+4pdn5ndfsDb7J5WEW91sgs0rPMVH6D8o8+p3R0Dqpr
         kKxwKYQ+sCYDLXwhf7eZ11xErUPjZciYiWYARkzo8nmupLdi7F39mO0mKqWggN51N0qc
         Fw8eVFWoiEgNgmoGFytrwJkoK4Ico520WQ5FqhC6AYmF6DNATnU/IugbLBsNGQ8yS993
         vPcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=TBcpwAm/9gesggEiSRqYAVJS5WV5h717wc5PrdbeLYo=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=h9E9u9yNtCglc8kKvTk2YYW96n2VD0tpATjKaTH85Ng2poQQMLtaQSQNZEtbwjwIVz
         AUGdgmEmz+0O4YPQtdpyZPZXLXXMooOhSV+gAbddO9SiK7eXlVYYhL6czMMGeC1Oztb+
         QnhhFZ4mMuuXigKranbUqXgtUJyTFBbC9ZLmoyN1tNZv5etZD+cCILzISOeAk80yczrW
         uvw40hzXLz5X55Rplteao8J3RVaQlEiG1CisPKrBBahADgQfR1cjPI3MAmtzrRk+ABmh
         2Dojwkh+Xy7uYWvYUYPII/qtnZTjPl0x+zDC8zp6+fW71zi6VSn5rBvj39dvgRUudA93
         vtyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=zHFYnHDo;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=rv8GsTOQ;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=zHFYnHDo;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=rv8GsTOQ;
       spf=pass (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704269840; x=1704874640; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TBcpwAm/9gesggEiSRqYAVJS5WV5h717wc5PrdbeLYo=;
        b=YjwvzQdQzXzQTJawni1I01mZVX4xOShGcbir32xpMwvhBpjjgdVVIUdjQUOiczZ1FM
         AaX5r7LVY30OQSX09bynoZYgJuJeqdNam0U4+yieSZogfdE+yCIpwBilbEB5GjzOc1hD
         AC2MEVG5jA6sVAsuCyGjRx9s8pyAgkxdDPM1JNNQGKj/QZ26inz+InS9z+usqOI/z2m2
         Yl6dNZzFm9t7bapySvpbFeUMsGLZpVUNy8210BdaKnLh53c+Ygr5wjJBkQy5GA2TeWoG
         1yH/WrVBXjFpn1j/rgo01VSE62/Dho35jivHOR3Q4axcYiNPUMytytBALkF323puE7lF
         DYhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704269840; x=1704874640;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TBcpwAm/9gesggEiSRqYAVJS5WV5h717wc5PrdbeLYo=;
        b=IWqtjGO4Lf0FyUlkRYTXWBn0UxTlyU3pW1LeDRmCax5ji/1Q2ed/Dlk8iIg+56KI2m
         rzZXWdnrPo198vMSdU7f9mcTQY5a6pjLwN5DEpM2c4R44qI9SSu8misYkY2cK4pL1moN
         DwFWRTLDLkXzmmISU+2U+LVQRRuYapMoMBx2/eCjE/c321n8wLHawhp4WihmEFtk0tso
         LBW0yTVqV14ytr5TdsSFidz69bGf4AiWOpfkC+HPAnICxWLiKZ54T7lqfBlbH7P33M4+
         2khhPOf3zYKZDGruOia5TEVFpaKGPhGMoYB/WA+BTopQK/MJLD5AcAaFX0uD8ZSmbbYv
         /1EA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzOQ9+zSrC9p9Y5tUm1liPGmb56fJjFnUmE4lm1nS+AimI1Pzu3
	RuSxzD0WTNbsB/ohyF9DefA=
X-Google-Smtp-Source: AGHT+IHi+PUV0AP36xkZE/yBTB3Gh7G1VTjy1h3jxNuvhxX740Lx8vGnS7kaB3azCfeS1vZebqiiRw==
X-Received: by 2002:a05:600c:2192:b0:40d:7b84:621d with SMTP id e18-20020a05600c219200b0040d7b84621dmr3720071wme.126.1704269838662;
        Wed, 03 Jan 2024 00:17:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1913:b0:40d:3abd:bd07 with SMTP id
 j19-20020a05600c191300b0040d3abdbd07ls3053836wmq.0.-pod-prod-03-eu; Wed, 03
 Jan 2024 00:17:17 -0800 (PST)
X-Received: by 2002:a1c:7918:0:b0:40d:8885:ab2d with SMTP id l24-20020a1c7918000000b0040d8885ab2dmr1852560wme.29.1704269837062;
        Wed, 03 Jan 2024 00:17:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704269837; cv=none;
        d=google.com; s=arc-20160816;
        b=p0Z51G2LLsN5kjLrfh1Cm4jUYQu9WaKlHaolkTOV/6knCD3/HhRDuOy/97CwsX7w7d
         Dkj4+0RRGxwbzqDvECAX+0ZmpWvMS35u345IGl06gIRN2CCdRgrOBZxDkF7atvrxaZY8
         sWpRPVgX8GmE3BAsBqBfljUKp6qYNSR4IzNeh4feimnqcM5FcNjZASy5BaLRZTREnfI1
         fPSJkuhcsj+DK2lCzTL4DYwzUXXb0xHmuJz9EdBLCdmmY5salVW8W874/JDFko96Hqgn
         lyG89d2RIeYe+EXJYhwBWfmIQaBN58/MHIab53XOrPtcbMy0N892XEZiguuEfHMFOyCT
         j6mA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=0c8L09+ASNGdeweZZGc2435Rju4Eh2hqzG4gk5W9zvE=;
        fh=uYnjiVNxbW5kI0u75v8U/Y/ao7NQ4m8EfWg99NPaynw=;
        b=p/lG6i9sZy3bFKCdZKDQ3soSlFmUIVXyX2mB+wS3gmsQc5FpsSSD26M5TLPIDHXbdM
         iIyD356AjaQZEnbGdBp9z/AZp/HDgNCZl38gch7Z0sBV5RLKyPgdTtWvk5boUR5sjZZf
         zgeNG5Zti04nKPpPXDjOVJmxnL8BmtgL03nrYlqTjpnHUBV4gqcKphlsW4lZ52TLC4+c
         pYj65aaeKEvsJbG9asyB1+YOuL4G3JPhyE+K/CFqIHVA/T9nRnZsQ17UrqxGrdX+WfNG
         aKqQhtbUkrJCKde0cFm1uFTFDVRL8N3evwUtvVyDVnL9+ePtI+WOiANwmTbdulSO81kK
         227g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=zHFYnHDo;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=rv8GsTOQ;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=zHFYnHDo;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=rv8GsTOQ;
       spf=pass (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id l18-20020a05600c1d1200b0040d5b7b8402si33106wms.0.2024.01.03.00.17.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jan 2024 00:17:17 -0800 (PST)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 7C13C1F79B;
	Wed,  3 Jan 2024 08:17:16 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id C32251340C;
	Wed,  3 Jan 2024 08:17:15 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id HuPaLAsYlWWGWwAAD6G6ig
	(envelope-from <osalvador@suse.de>); Wed, 03 Jan 2024 08:17:15 +0000
Date: Wed, 3 Jan 2024 09:18:06 +0100
From: Oscar Salvador <osalvador@suse.de>
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v4 02/22] lib/stackdepot: check disabled flag when
 fetching
Message-ID: <ZZUYPuk4dNG6f4Cc@localhost.localdomain>
References: <cover.1700502145.git.andreyknvl@google.com>
 <c3bfa3b7ab00b2e48ab75a3fbb9c67555777cb08.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c3bfa3b7ab00b2e48ab75a3fbb9c67555777cb08.1700502145.git.andreyknvl@google.com>
X-Spam-Level: 
X-Spam-Level: 
X-Spamd-Result: default: False [-0.11 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[12];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.de:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,google.com,suse.cz,googlegroups.com,kvack.org,vger.kernel.org];
	 RCVD_TLS_ALL(0.00)[];
	 BAYES_HAM(-0.01)[51.07%]
X-Spam-Score: -0.11
X-Spam-Flag: NO
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=zHFYnHDo;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519 header.b=rv8GsTOQ;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=zHFYnHDo;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519
 header.b=rv8GsTOQ;       spf=pass (google.com: domain of osalvador@suse.de
 designates 2a07:de40:b251:101:10:150:64:2 as permitted sender)
 smtp.mailfrom=osalvador@suse.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
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

On Mon, Nov 20, 2023 at 06:47:00PM +0100, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Do not try fetching a stack trace from the stack depot if the
> stack_depot_disabled flag is enabled.
> 
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Oscar Salvador <osalvador@suse.de>


-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZZUYPuk4dNG6f4Cc%40localhost.localdomain.
