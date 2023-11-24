Return-Path: <kasan-dev+bncBDXYDPH3S4OBBTWYQGVQMGQEVHVW5XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id CF7277F6F7E
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Nov 2023 10:26:40 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-6c334d2fd4csf1841678b3a.2
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Nov 2023 01:26:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700817999; cv=pass;
        d=google.com; s=arc-20160816;
        b=PV9pv7zZpKmfaY92idSqOlG8tfNlLjjZJEGS3JwAKTvU977UJIuRku1ZEMjqk2g8AK
         lA7QldcgDkWxs0mFuQ9vJ6uy2jBqWHxCrhT9utc9uOSsyEej2RNvXrmc9bfUtOHFnEI5
         fHOf/Ng2HmALSq5lBJbEmz7oMZbgvYbPglun0xmyhEaECFlVnArZBk4lN2KOFwc0j52G
         9capN0/JRAzA6l5huGeAm43CSIOOsjIe9mjfnTwhoZNz1CIFfIeLErbYHantuLA3xhFB
         yil4mYHL9MaE+Vom8l3BVl9hQQh7ZzdmpgYsZDL8T2eJgCl/wtcEdEZmhoYx+WAH3bpZ
         kIrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=9IwApfyFos8vJ4Cm2DJjER/3c5EpMER5BQbNcJuZxbs=;
        fh=BbELjiKDpogQBABjZcqeHo2dtHt5oIJN1+5JylGausM=;
        b=nlwrVigwMCr6Cjb5P3bsGTaRvrQclmi8cPPkvBx/cMkBRIOBXys0J78J30lCaYYqjv
         ZnsloHH+anUrMRuR98bhik1jUAVAEggdlBbLnOutTmdrh/pzn3EYpxUqiBH6VaNs6v4X
         nXIJtnhEzfuOIkNvPyK6ax8W0AXk2f/Eg4/Phsr7Zj9Mh8pzb5xhjQq3rzbOQlcLlVXG
         E/pKbYCi7TX41j+xAtTNPDF4ghTfXa4ZG5mlzLWdqt3L2SS5CC7yz1b9ohgunxvJsL48
         bL0/WxG8GobS1xgsSHgLnanWf/+Dn/lz+efTw8eY4NO8zgh8tK1zuRddq7EACq1prYlM
         Duzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wi7zjCRT;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=0W5OjFqN;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700817999; x=1701422799; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=9IwApfyFos8vJ4Cm2DJjER/3c5EpMER5BQbNcJuZxbs=;
        b=VWPQ2liwKNVWOanly/vvoe5sNcByhN8VaNbGfDr0guJeGDtazpRFSqOIUZ17OVFL1O
         rN2RwvY1hIcbpC1ors0nl7u5M8E05LnEQ1f8jfWDuyNZ1NgNbXYXsVCzIoE0Vh9W3Ri8
         km0gWz/l2rfHedOfSk7s25izpxaRgPBm+RzvO3gTtF87RJLDXdJMPqzK2Vk0/y0cTm4W
         9RUjrHYUloCfLQVcDN3sIJnjHGX3JcOi4WPeC9JLkKZ9nIWlt13anzJxduvcykgV9+8r
         A6yXJwLP6ZB25xeR3sihd6fpcFiEch/ldBqNa+8+/8adq1GI7QWAz5/8XhDCzp4nBFsI
         OrNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700817999; x=1701422799;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9IwApfyFos8vJ4Cm2DJjER/3c5EpMER5BQbNcJuZxbs=;
        b=aOU5b4YFkkL3pUF2i3+ba7Da/peVosp5lNfMoGYUeZwUo+zuuqUlvPfNlck/hLm9sC
         nP2pls/auiVWPTVhf910LBYjlQ7wWBcvgOTb/uSmNkM1NOi9R1+I3MLzNJKGl+NgFvTy
         vwVTovaBfBEdm5217FcJcF+usr8u103Sj0Zc+YxuioDJLtWAAWTo/0dE/rFLHLWNrz6t
         63o1lPK6T+07YohqVMcXuTdw6iQLBA4sQQ6tOOrioKz6CrPEL7fSO8x7hWSGm0H2hFyy
         usZiVryv2lebCkpP0T36ueQVK75SjUhXNBHOYv/jVky8m/+a33N/MqjRRq4uHVzX3JYM
         94JQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyhC/sNMvWvPebGoVhV2yjVv0yc9eKYItziHH710jWIbixWJoJJ
	cubIKUsS6iJFSY3Re+l7dgY=
X-Google-Smtp-Source: AGHT+IGCo+8xJsun/Nlfmxo7UCYBs1SC2tvZ8py84ETDBeb1CKt3qbwu5ZdOcXE7fe37pwi2KgSASg==
X-Received: by 2002:a05:6a00:130f:b0:6cb:a60c:1d with SMTP id j15-20020a056a00130f00b006cba60c001dmr2055496pfu.17.1700817999112;
        Fri, 24 Nov 2023 01:26:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:21d4:b0:6cb:735c:685a with SMTP id
 t20-20020a056a0021d400b006cb735c685als1269719pfj.1.-pod-prod-05-us; Fri, 24
 Nov 2023 01:26:38 -0800 (PST)
X-Received: by 2002:a05:6a21:998d:b0:187:a2ca:409c with SMTP id ve13-20020a056a21998d00b00187a2ca409cmr2434779pzb.5.1700817998064;
        Fri, 24 Nov 2023 01:26:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700817998; cv=none;
        d=google.com; s=arc-20160816;
        b=GzT/MtaHit/AGy164uJlwLl8jvBYLvcRsEaoYXJTAeWfdHg0o4QA630zHc8nMvMJYG
         /MxK5D1tAjvDz3uFH9bUqkYd3QN1gg2yf3MWxGz2jptA2TDHyHt/7Ehcoq4cWdBFE0tJ
         pNyGABmpTYtv3uHtzP57zG0eo+5HwY8GvBMvOVRRmHaglmBivMS2A8T8h6qiYQnlbSIC
         UYu6wVwuKA7rvy0nV43Vs1JOSZeqdlWcIFbX1QZHN6dV99dTHHXZM96/SZK/FwRcoE9c
         lIw72caNovi9UqezJr1EaUWmtzSr2UkudugliXHa9baNuJ0gpNAVqfm9LfwOvNYMbvBE
         Hp7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=9LgMMddRm1Z0VKUmKvdY8oWuzJ6UIJ2B5WVeljH1gzY=;
        fh=BbELjiKDpogQBABjZcqeHo2dtHt5oIJN1+5JylGausM=;
        b=ipePGhfKa2n4knaRYrcCILRfWjzUcFydIfc9YeC07NLH0GXHGX6nF/+6/MLSGcJWCc
         dGCi4qvgiN4fVXrYEDO+nJF55Y3THyDuT4EoNLvAOM/MeUViXEQspUY8LabOEPwgsKo9
         IFjCcwX4tBQ5lzSnk6dPSeomhqGR2nNz/PP60YVGOWqKRrbl2+jlYdezVZcBoemlaTqT
         G5mAQAvQV0ivzNBPQZbaiXfLTjMHWXMvLcg68OFuJA5+1num2hPRb0QkZ1DNY9Sj1iOY
         pEcEvaYyiDiY7u/o+9H47HzZrSLDZXIkIXgq4k6fCRdhj1qZO08yPCAIIdd5gHQZk2Lb
         0/ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wi7zjCRT;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=0W5OjFqN;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id nm1-20020a17090b19c100b00285105ac839si178667pjb.0.2023.11.24.01.26.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Nov 2023 01:26:37 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 05E2E21CC1;
	Fri, 24 Nov 2023 09:26:36 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id CB51D13A98;
	Fri, 24 Nov 2023 09:26:35 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 739GMUtsYGVxZQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 24 Nov 2023 09:26:35 +0000
Message-ID: <2d0626b2-793c-315f-dc93-af021bd5cb85@suse.cz>
Date: Fri, 24 Nov 2023 10:26:35 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH v2 00/21] remove the SLAB allocator
Content-Language: en-US
To: David Rientjes <rientjes@google.com>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver
 <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>,
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>,
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
 linux-hardening@vger.kernel.org, Michal Hocko <mhocko@suse.com>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <b4d53ec4-482d-23ec-b73f-dfbc58ccc149@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <b4d53ec4-482d-23ec-b73f-dfbc58ccc149@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: 0.20
X-Spam-Flag: NO
X-Spam-Level: 
X-Spamd-Result: default: False [0.20 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 BAYES_SPAM(0.00)[35.47%];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[24];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux.com,kernel.org,lge.com,linux-foundation.org,gmail.com,linux.dev,google.com,arm.com,cmpxchg.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com,suse.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=wi7zjCRT;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=0W5OjFqN;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/24/23 01:45, David Rientjes wrote:
> On Mon, 20 Nov 2023, Vlastimil Babka wrote:
> 
>> Changes from v1:
>> - Added new Patch 01 to fix up kernel docs build (thanks Marco Elver)
>> - Additional changes to Kconfig user visible texts in Patch 02 (thanks Kees
>>   Cook)
>> - Whitespace fixes and other fixups (thanks Kees)
>> 
>> The SLAB allocator has been deprecated since 6.5 and nobody has objected
>> so far. As we agreed at LSF/MM, we should wait with the removal until
>> the next LTS kernel is released. This is now determined to be 6.6, and
>> we just missed 6.7, so now we can aim for 6.8 and start exposing the
>> removal to linux-next during the 6.7 cycle. If nothing substantial pops
>> up, will start including this in slab-next later this week.
>> 
> 
> I agree with the decision to remove the SLAB allocator, same as at LSF/MM.  
> Thanks for doing this, Vlastimil!
> 
> And thanks for deferring this until the next LTS kernel, it will give any 
> last minute hold outs a full year to raise any issues in their switch to 
> SLUB if they only only upgrade to LTS kernels at which point we'll have 
> done our due diligence to make people aware of SLAB's deprecation in 6.6.
> 
> I've completed testing on v1 of the series, so feel free to add
> 
> Acked-by: David Rientjes <rientjes@google.com>
> Tested-by: David Rientjes <rientjes@google.com>

Thanks! And others too.

I've now pushed this series to slab/for-6.8/slab-removal and slab/for-next


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2d0626b2-793c-315f-dc93-af021bd5cb85%40suse.cz.
